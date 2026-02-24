"""
LLMMixin — OpenAI and Anthropic API call wrappers, cost tracking.
"""
import json
import uuid
from types import SimpleNamespace

from config import load_config
from pricing import resolve_model_rates
from prompts import CTF_TOOLS, ANTHROPIC_TOOLS
from db import update_challenge


class LLMMixin:

    def _emit_cost_live(self, extra_out: int):
        """Emit a running cost estimate during streaming without updating totals or DB."""
        _, rates = resolve_model_rates(self.model, load_config())
        if not rates:
            return
        ir, or_ = rates
        cum_in = self._base_tokens_in + self.total_in
        cum_out = self._base_tokens_out + self.total_out + extra_out
        est = (cum_in * ir + cum_out * or_) / 1_000_000
        self.emit("cost", {
            "cost": f"~${est:.4f}",
            "cost_usd": est,
            "tokens_in": cum_in,
            "tokens_out": cum_out,
            "model": self.model,
            "known": True,
        })

    def _emit_cost(self, in_tokens: int, out_tokens: int):
        self.total_in += max(0, int(in_tokens or 0))
        self.total_out += max(0, int(out_tokens or 0))
        cum_in = self._base_tokens_in + self.total_in
        cum_out = self._base_tokens_out + self.total_out
        _, rates = resolve_model_rates(self.model, load_config())
        if rates:
            ir, or_ = rates
            run_cost = (self.total_in * ir + self.total_out * or_) / 1_000_000
            base_cost = 0.0 if self._base_cost_usd is None else float(self._base_cost_usd)
            cost = base_cost + run_cost
            update_challenge(self.cid, cost_usd=cost, tokens_in=cum_in, tokens_out=cum_out)
            payload = {
                "cost": f"${cost:.4f}",
                "cost_usd": cost,
                "tokens_in": cum_in,
                "tokens_out": cum_out,
                "model": self.model,
                "known": True,
            }
        else:
            update_challenge(self.cid, tokens_in=cum_in, tokens_out=cum_out)
            payload = {
                "cost": "—",
                "cost_usd": self._base_cost_usd,
                "tokens_in": cum_in,
                "tokens_out": cum_out,
                "model": self.model,
                "known": False,
            }
        self.emit("cost", payload)

    def _anthropic_messages_from_history(self, messages: list[dict]) -> list[dict]:
        out = []
        for m in messages:
            role = m.get("role")
            if role == "user":
                out.append({"role": "user", "content": str(m.get("content") or "")})
                continue
            if role == "assistant":
                blocks = []
                text = m.get("content")
                if text:
                    blocks.append({"type": "text", "text": str(text)})
                for tc in m.get("tool_calls") or []:
                    fn = tc.get("function") or {}
                    raw_args = fn.get("arguments", {})
                    if isinstance(raw_args, str):
                        try:
                            parsed_args = json.loads(raw_args) if raw_args.strip() else {}
                        except Exception:
                            parsed_args = {}
                    elif isinstance(raw_args, dict):
                        parsed_args = raw_args
                    else:
                        parsed_args = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.get("id") or f"toolu_{uuid.uuid4().hex[:12]}",
                        "name": fn.get("name", ""),
                        "input": parsed_args if isinstance(parsed_args, dict) else {},
                    })
                if blocks:
                    out.append({"role": "assistant", "content": blocks})
                continue
            if role == "tool":
                tcid = m.get("tool_call_id")
                if not tcid:
                    continue
                out.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": tcid,
                        "content": str(m.get("content") or ""),
                    }],
                })
        return out

    def _call_openai(self, force_text=False):
        if not self.openai_client:
            raise RuntimeError("OpenAI model selected but no OpenAI key configured. Set openai_api_key in config.json or OPENAI_API_KEY.")
        msg_list = self._sanitize_messages(self.messages)
        kwargs = dict(
            model=self.model,
            **self._token_limit_kw(4096),
            messages=[{"role": "system", "content": self._system_prompt()}] + msg_list,
            stream=True,
            stream_options={"include_usage": True},
        )
        if not force_text:
            kwargs["tools"] = CTF_TOOLS
            kwargs["tool_choice"] = "auto"

        stream = self.openai_client.chat.completions.create(**kwargs)
        content_parts = []
        tool_calls = {}
        usage = None
        stream_id = uuid.uuid4().hex
        msg_type = "reasoning"
        started = False
        out_count = 0
        last_cost_emit = 0

        for chunk in stream:
            if not self.running:
                try:
                    stream.close()
                except Exception:
                    pass
                break
            if getattr(chunk, "usage", None):
                usage = chunk.usage
            if not chunk.choices:
                continue
            delta = chunk.choices[0].delta
            if not delta:
                continue
            if getattr(delta, "content", None):
                if not started:
                    self.emit("thought_stream_start", {"id": stream_id, "type": msg_type})
                    started = True
                text = delta.content
                content_parts.append(text)
                self._emit_stream_delta(stream_id, text, msg_type)
                out_count += max(1, len(text) // 4)
                if out_count - last_cost_emit >= 25:
                    last_cost_emit = out_count
                    self._emit_cost_live(out_count)
            if getattr(delta, "tool_calls", None):
                for tc in delta.tool_calls:
                    idx = tc.index
                    if idx not in tool_calls:
                        tool_calls[idx] = {"id": tc.id, "type": tc.type, "function": {"name": "", "arguments": ""}}
                    if tc.id:
                        tool_calls[idx]["id"] = tc.id
                    if tc.function:
                        if tc.function.name:
                            tool_calls[idx]["function"]["name"] = tc.function.name
                        if tc.function.arguments:
                            tool_calls[idx]["function"]["arguments"] += tc.function.arguments

        if started:
            self.emit("thought_stream_end", {"id": stream_id})

        if usage:
            self._emit_cost(usage.prompt_tokens, usage.completion_tokens)

        content = "".join(content_parts) if content_parts else None
        tc_objs = None
        tc_raw = None
        if tool_calls:
            ordered = [tool_calls[i] for i in sorted(tool_calls.keys())]
            tc_objs = []
            tc_raw = []
            for t in ordered:
                fn = SimpleNamespace(name=t["function"]["name"], arguments=t["function"]["arguments"])
                tc_objs.append(SimpleNamespace(id=t["id"], type=t.get("type", "function"), function=fn))
                tc_raw.append({
                    "id": t["id"],
                    "type": t.get("type", "function"),
                    "function": {
                        "name": t["function"]["name"],
                        "arguments": t["function"]["arguments"],
                    },
                })

        return SimpleNamespace(content=content, tool_calls=tc_objs, tool_calls_raw=tc_raw)

    def _call_anthropic(self, force_text=False):
        from anthropic import Anthropic
        if Anthropic is None:
            raise RuntimeError("Anthropic package is not installed. Run: pip install -r requirements.txt")
        if not self.anthropic_client:
            raise RuntimeError("Anthropic model selected but no Anthropic key configured. Set anthropic_api_key in config.json or ANTHROPIC_API_KEY.")

        msg_list = self._sanitize_messages(self.messages)
        anthropic_messages = self._anthropic_messages_from_history(msg_list)
        kwargs = {
            "model": self.model,
            "max_tokens": 4096,
            "system": self._system_prompt(),
            "messages": anthropic_messages,
        }
        if not force_text:
            kwargs["tools"] = ANTHROPIC_TOOLS
            kwargs["tool_choice"] = {"type": "auto"}

        text_parts = []
        tc_objs = []
        tc_raw = []
        stream_id = uuid.uuid4().hex
        started = False
        current_tool = None   # {id, name, args_json}
        in_tokens = 0
        out_tokens = 0
        out_est = 0
        last_cost_emit = 0

        with self.anthropic_client.messages.stream(**kwargs) as stream:
            for event in stream:
                if not self.running:
                    break
                etype = getattr(event, "type", "")

                if etype == "message_start":
                    u = getattr(getattr(event, "message", None), "usage", None)
                    if u:
                        in_tokens = (
                            int(getattr(u, "input_tokens", 0) or 0)
                            + int(getattr(u, "cache_creation_input_tokens", 0) or 0)
                            + int(getattr(u, "cache_read_input_tokens", 0) or 0)
                        )

                elif etype == "content_block_start":
                    block = getattr(event, "content_block", None)
                    if block and getattr(block, "type", "") == "tool_use":
                        current_tool = {
                            "id": getattr(block, "id", f"toolu_{uuid.uuid4().hex[:12]}"),
                            "name": getattr(block, "name", ""),
                            "args_json": "",
                        }

                elif etype == "content_block_delta":
                    delta = getattr(event, "delta", None)
                    if delta:
                        dtype = getattr(delta, "type", "")
                        if dtype == "text_delta":
                            text = getattr(delta, "text", "")
                            if text:
                                text_parts.append(text)
                                if not started:
                                    self.emit("thought_stream_start", {"id": stream_id, "type": "reasoning"})
                                    started = True
                                self._emit_stream_delta(stream_id, text, "reasoning")
                                out_est += max(1, len(text) // 4)
                                if out_est - last_cost_emit >= 25:
                                    last_cost_emit = out_est
                                    self._emit_cost_live(out_est)
                        elif dtype == "input_json_delta" and current_tool is not None:
                            current_tool["args_json"] += getattr(delta, "partial_json", "")

                elif etype == "content_block_stop":
                    if current_tool is not None:
                        try:
                            input_obj = json.loads(current_tool["args_json"] or "{}")
                        except Exception:
                            input_obj = {}
                        args_json = json.dumps(input_obj, ensure_ascii=False)
                        fn = SimpleNamespace(name=current_tool["name"], arguments=args_json)
                        tc_objs.append(SimpleNamespace(id=current_tool["id"], type="function", function=fn))
                        tc_raw.append({
                            "id": current_tool["id"],
                            "type": "function",
                            "function": {"name": current_tool["name"], "arguments": args_json},
                        })
                        current_tool = None

                elif etype == "message_delta":
                    u = getattr(event, "usage", None)
                    if u:
                        out_tokens = int(getattr(u, "output_tokens", 0) or 0)

        if started:
            self.emit("thought_stream_end", {"id": stream_id})

        self._emit_cost(in_tokens, out_tokens)

        content = "".join(text_parts) if text_parts else None
        return SimpleNamespace(
            content=content,
            tool_calls=tc_objs or None,
            tool_calls_raw=tc_raw or None,
        )

    def _call(self, force_text=False):
        # Always prune dangling tool_calls before sending to API.
        self._prune_dangling_tool_calls()
        if self.provider == "anthropic":
            return self._call_anthropic(force_text=force_text)
        return self._call_openai(force_text=force_text)
