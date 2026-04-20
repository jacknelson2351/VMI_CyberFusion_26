"""
CTFAgentCore — base class with __init__, run loop, dispatch, and helpers.
"""
import ast
import hashlib
import json
import os
import re
import threading
import time
import uuid
from collections import deque
from copy import deepcopy
from types import SimpleNamespace

from openai import OpenAI
try:
    from anthropic import Anthropic
except Exception:
    Anthropic = None

from extensions import socketio
from config import load_config, _as_bool, _canonical_launch_model, _is_anthropic_model
from prompts import (
    CATEGORY_PROMPTS, COMPACT_BASE_RULES, CATEGORY_EXECUTION_BRIEFS,
    BASE_RULES, STEP_LIMITS,
)
from utils import _is_approval_seeking_text, _shell_quote
from pricing import _infer_pip_package
from db import get_challenge, update_challenge
from agent.registry import _log_event
from .state import ChallengeMemoryStore
from storage import utc_now_iso


class CTFAgentCore:

    def __init__(
        self,
        cid,
        category,
        container,
        room,
        flag_format="",
        model: str | None = None,
        challenge_name: str = "",
        challenge_description: str = "",
        base_tokens_in: int = 0,
        base_tokens_out: int = 0,
        base_cost_usd: float | None = 0.0,
    ):
        cfg          = load_config()
        self.cfg     = cfg
        self.cid     = cid
        self.category= category
        self.container = container
        self.room    = room  # socket.io room = challenge id
        self.flag_format = (flag_format or "").strip()
        self.challenge_name = (challenge_name or "").strip()
        self.challenge_description = challenge_description or ""
        cfg_model = (cfg.get("model") or "gpt-4o")
        self.model   = ((_canonical_launch_model(model) or cfg_model).strip() or "gpt-4o")
        self.provider = "anthropic" if _is_anthropic_model(self.model) else "openai"
        openai_key = cfg.get("openai_api_key") or os.environ.get("OPENAI_API_KEY")
        anthropic_key = cfg.get("anthropic_api_key") or os.environ.get("ANTHROPIC_API_KEY")
        self.openai_client = OpenAI(api_key=openai_key) if openai_key else None
        self.anthropic_client = (
            Anthropic(api_key=anthropic_key)
            if anthropic_key and Anthropic is not None
            else None
        )
        self.prompt_profile = (cfg.get("prompt_profile") or "compact").strip().lower()
        self.allow_runtime_installs = _as_bool(cfg.get("allow_runtime_installs"), default=False)
        self.strict_auto_submit = _as_bool(cfg.get("strict_auto_submit"), default=True)
        self.allow_nonstandard_submit = _as_bool(cfg.get("allow_nonstandard_submit"), default=False)
        self.tool_context_limit = int(cfg.get("tool_context_limit") or 4000)
        self.hypothesis_budget = int(cfg.get("hypothesis_budget") or 2)
        self.max_tool_calls_per_turn = max(1, min(int(cfg.get("max_tool_calls_per_turn") or 3), 6))
        self.messages= []
        self.running = False
        self.step    = 0
        # Per-run token counters; cumulative challenge totals are base + run counters.
        self.total_in= 0
        self.total_out=0
        self._base_tokens_in = max(0, int(base_tokens_in or 0))
        self._base_tokens_out = max(0, int(base_tokens_out or 0))
        self._base_cost_usd = None if base_cost_usd is None else float(base_cost_usd or 0.0)
        self._recent_cmds = deque(maxlen=30)
        self._tool_preflight_done = False
        self._install_attempted_tools = set()
        self._seen_output_fingerprints = set()
        self._family_no_progress = {}
        self._last_tool_progress = False
        self._no_progress_steps = 0
        self._hint_map = {}
        self._hint_attempted = set()
        self._hint_injected = set()          # which tool:value directives have already been injected
        self._pending_directive_messages = [] # flushed AFTER the tool loop, never mid-dispatch
        self._guidance_keys_sent = set()
        self._tool_output_first_seen_step = {}
        self._running_hint_action = False
        self._last_cmd_status = {}   # cmd -> {"error": bool}
        self._preflight_missing_tools = []
        self._evidence_confirmed = []
        self._evidence_ruled_out = []
        self._next_hypothesis = ""
        self._evidence_version = 0
        self._hypothesis_no_progress = {}
        self._flag_evidence = {}
        self.memory = ChallengeMemoryStore(self.cid)
        self.run_state = {}
        self.hypotheses = []
        self.facts_doc = {}
        self.artifacts_doc = []
        self.dead_ends_doc = []
        self.candidates_doc = {}
        self._needs_replan = True
        self._active_hypothesis = None

    def emit(self, event, data):
        if not self.running and event in {"plan", "thought", "command", "output", "flag", "cost"}:
            return
        payload = dict(data or {})
        payload["cid"] = self.cid
        socketio.emit(event, payload, room=self.room)
        if event in {"plan", "thought", "command", "output", "flag", "done", "error"}:
            _log_event(self.cid, event, payload)

    def _trace_loop(self, phase: str, **fields):
        payload = {
            "cid": self.cid,
            "step": int(self.step or 0),
            "phase": phase,
        }
        payload.update(fields or {})
        socketio.emit("loop_trace", payload, room=self.room)
        _log_event(self.cid, "loop_trace", payload)

    def start(self, challenge_desc: str, prior_summary: str | None = None):
        self.running = True
        threading.Thread(
            target=self._run,
            args=(challenge_desc, prior_summary),
            daemon=True
        ).start()

    def stop(self):
        self.running = False

    def _finalize_flag_candidate(self, flag: str, how: str = "", source: str = "") -> bool:
        candidate = (flag or "").strip()
        if not candidate:
            return False
        update_challenge(
            self.cid,
            status="pending_approval",
            flag=None,
            flag_candidate=candidate,
            flag_how=(how or "").strip(),
            writeup_md=None,
            writeup_path=None,
            writeup_ready_at=None,
            approved_at=None,
        )
        self._append_memory_entry(
            self.candidates_doc.setdefault("flags", []),
            "value",
            candidate,
            status="pending_approval",
            source=source or "agent",
            step=int(self.step or 0),
        )
        self.run_state.update({
            "status": "pending_approval",
            "phase": "done",
        })
        self._save_memory_documents()
        self.running = False
        self.emit("thought", {
            "text": f"Flag candidate found: {candidate}. Awaiting user approval.",
            "type": "system",
        })
        self.emit("flag", {
            "flag": candidate,
            "how": how,
            "pending_approval": True,
            "source": source or "agent",
        })
        self.emit("done", {
            "status": "pending_approval",
            "flag": candidate,
            "message": "Flag candidate found. Validate it and approve to finalize + generate writeup.",
        })
        return True

    def _system_prompt(self):
        if self.prompt_profile == "full":
            return CATEGORY_PROMPTS.get(self.category, BASE_RULES)
        brief = CATEGORY_EXECUTION_BRIEFS.get(self.category, "Use hypothesis-driven, evidence-first workflow.")
        return COMPACT_BASE_RULES + "\nCategory focus: " + brief

    def _token_limit_kw(self, max_tokens: int, model_name: str | None = None) -> dict:
        # Newer reasoning models (e.g., o1/o3/gpt-5) use max_completion_tokens.
        model = (model_name or self.model or "").lower()
        if model.startswith(("o1", "o3", "gpt-5")):
            return {"max_completion_tokens": max_tokens}
        return {"max_tokens": max_tokens}

    def _truncate_for_context(self, text: str) -> str:
        if not text:
            return "(no output)"
        if len(text) <= self.tool_context_limit:
            return text
        return text[:self.tool_context_limit] + "\n...[truncated]..."

    def _is_answer_style_challenge(self) -> bool:
        text = f"{self.challenge_name}\n{self.challenge_description}".lower()
        if not text.strip():
            return False
        cues = (
            "each correct answer solves one flag",
            "questions",
            "what file type",
            "what type of packer",
            "once you unpack",
            "cost:",
        )
        score = sum(1 for c in cues if c in text)
        return score >= 2

    def _sanitize_messages(self, messages: list[dict]) -> list[dict]:
        # Ensure tool role messages only appear after a matching assistant tool_calls message.
        out = []
        expected_tool_ids = set()
        for m in messages:
            role = m.get("role")
            if role == "assistant" and m.get("tool_calls"):
                expected_tool_ids = {tc.get("id") for tc in m.get("tool_calls", []) if tc.get("id")}
                out.append(m)
                continue
            if role == "tool":
                if expected_tool_ids and m.get("tool_call_id") in expected_tool_ids:
                    out.append(m)
                # else drop orphan tool message
                continue
            # normal user/assistant/system
            expected_tool_ids = set()
            out.append(m)
        return out

    def _prune_dangling_tool_calls(self):
        # Keep only complete assistant(tool_calls) -> tool(response...) blocks.
        src = self.messages
        pruned = []
        i = 0
        n = len(src)
        while i < n:
            m = src[i]
            if m.get("role") == "assistant" and m.get("tool_calls"):
                expected = {tc.get("id") for tc in m.get("tool_calls", []) if tc.get("id")}
                j = i + 1
                block_tools = []
                seen = set()
                while j < n and src[j].get("role") == "tool":
                    t = src[j]
                    tcid = t.get("tool_call_id")
                    if tcid in expected and tcid not in seen:
                        block_tools.append(t)
                        seen.add(tcid)
                    j += 1
                # Keep the block only if every tool_call_id has a matching tool response.
                if expected and seen == expected:
                    pruned.append(m)
                    pruned.extend(block_tools)
                i = j
                continue
            # Drop orphan tool messages outright.
            if m.get("role") == "tool":
                i += 1
                continue
            pruned.append(m)
            i += 1
        self.messages = pruned

    def _emit_stream_delta(self, stream_id: str, text: str, msg_type: str):
        self.emit("thought_stream_delta", {"id": stream_id, "text": text, "type": msg_type})

    def _parse_tool_args(self, raw: str) -> tuple[dict, str | None]:
        """Best-effort tool args parser. Returns (args, error_message_or_None)."""
        if raw is None:
            return {}, "empty arguments"
        if isinstance(raw, dict):
            return raw, None
        s = (raw or "").strip()
        if not s:
            return {}, "empty arguments"
        # First try strict JSON.
        try:
            return json.loads(s), None
        except Exception:
            pass
        # Try to extract the first JSON object from noisy strings.
        try:
            start = s.find("{")
            end = s.rfind("}")
            if start != -1 and end != -1 and end > start:
                return json.loads(s[start:end + 1]), None
        except Exception:
            pass
        # Try Python literal dict with single quotes.
        try:
            val = ast.literal_eval(s)
            if isinstance(val, dict):
                return val, None
        except Exception:
            pass
        return {}, "invalid JSON arguments"

    def _record_command(self, cmd: str):
        if cmd:
            self._recent_cmds.append(cmd)

    def _append_user_guidance_once(self, content: str, key: str) -> bool:
        k = (key or "").strip()
        if not k:
            self.messages.append({"role": "user", "content": content})
            return True
        if k in self._guidance_keys_sent:
            return False
        self._guidance_keys_sent.add(k)
        self.messages.append({"role": "user", "content": content})
        return True

    def _queue_user_guidance_once(self, content: str, key: str) -> bool:
        k = (key or "").strip()
        if not k:
            self._pending_directive_messages.append({"role": "user", "content": content})
            return True
        if k in self._guidance_keys_sent:
            return False
        self._guidance_keys_sent.add(k)
        self._pending_directive_messages.append({"role": "user", "content": content})
        return True

    def _compact_tool_result_for_context(self, result: str) -> str:
        text = "" if result is None else str(result)
        if not text:
            return text
        h = hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()
        if h in self._tool_output_first_seen_step:
            first_step = self._tool_output_first_seen_step[h]
            return f"[same tool output as step {first_step}; sha1:{h[:10]}]"
        self._tool_output_first_seen_step[h] = int(self.step or 0)
        return text

    def _pre_llm_short_circuit(self) -> bool:
        # Deterministic guards that avoid unnecessary model-call attempts.
        if self.provider == "openai" and not self.openai_client:
            msg = "OpenAI model selected but no OpenAI key configured."
            self.running = False
            update_challenge(self.cid, status="unsolved")
            self.emit("error", {"message": msg})
            self.emit("done", {"status": "unsolved", "message": msg})
            return True
        if self.provider == "anthropic" and not self.anthropic_client:
            msg = "Anthropic model selected but no Anthropic key configured."
            self.running = False
            update_challenge(self.cid, status="unsolved")
            self.emit("error", {"message": msg})
            self.emit("done", {"status": "unsolved", "message": msg})
            return True
        return False

    def _summarize(self):
        self.emit("thought", {"text": "── Summarizing context ──", "type": "system"})
        if not self.openai_client:
            return
        try:
            # Avoid tool messages in the summary prompt to prevent invalid tool-call pairing.
            tail = [m for m in self.messages[-12:] if m.get("role") != "tool"]
            summary_model = "gpt-4o-mini"
            r = self.openai_client.chat.completions.create(
                model=summary_model, **self._token_limit_kw(400, model_name=summary_model),
                messages=[{"role": "user", "content":
                    "Summarize this CTF session: files found, tried, failed, theory, next steps.\n\n"
                    + json.dumps(tail, indent=2)}]
            )
            summary = r.choices[0].message.content or ""
            # Keep only summary + last few non-tool messages to avoid invalid tool history.
            tail2 = [m for m in self.messages[-3:] if m.get("role") != "tool"]
            self.messages = self.messages[:2] + [
                {"role": "user", "content": f"[SESSION SUMMARY]\n{summary}"}
            ] + tail2
        except Exception:
            pass

    def _save_retry_summary(self):
        try:
            overview = self.memory.load_all().get("overview", "").strip()
            if overview:
                update_challenge(self.cid, retry_summary=overview)
        except Exception:
            pass

    def _extract_json_payload(self, text: str, fallback):
        blob = (text or "").strip()
        if not blob:
            return deepcopy(fallback)
        candidates = [blob]
        for opener, closer in (("{", "}"), ("[", "]")):
            start = blob.find(opener)
            end = blob.rfind(closer)
            if start != -1 and end != -1 and end > start:
                candidates.append(blob[start:end + 1])
        for candidate in candidates:
            try:
                return json.loads(candidate)
            except Exception:
                continue
        return deepcopy(fallback)

    def _append_memory_entry(self, items: list, value_key: str, value: str, **extra) -> bool:
        text = str(value or "").strip()
        if not text:
            return False
        for item in items:
            if isinstance(item, dict) and str(item.get(value_key) or "").strip() == text:
                item.update({k: v for k, v in extra.items() if v not in (None, "", [])})
                item["updated_at"] = utc_now_iso()
                return False
            if not isinstance(item, dict) and str(item).strip() == text:
                return False
        payload = {value_key: text, "updated_at": utc_now_iso()}
        for key, val in extra.items():
            if val not in (None, "", []):
                payload[key] = val
        items.append(payload)
        return True

    def _load_memory_documents(self):
        loaded = self.memory.load_all()
        self.run_state = dict(loaded.get("state") or {})
        self.hypotheses = list(loaded.get("hypotheses") or [])
        self.facts_doc = dict(loaded.get("facts") or {})
        self.artifacts_doc = list(loaded.get("artifacts") or [])
        self.dead_ends_doc = list(loaded.get("dead_ends") or [])
        self.candidates_doc = dict(loaded.get("candidates") or {})
        self._evidence_confirmed = [
            item.get("text") if isinstance(item, dict) else str(item)
            for item in (self.facts_doc.get("confirmed") or [])
        ][-20:]
        self._evidence_ruled_out = [
            item.get("text") if isinstance(item, dict) else str(item)
            for item in (self.facts_doc.get("ruled_out") or [])
        ][-20:]
        self._evidence_version = len(self._evidence_confirmed) + len(self._evidence_ruled_out)
        self._needs_replan = not bool(self.hypotheses)

    def _save_memory_documents(self):
        self.run_state["last_updated_at"] = utc_now_iso()
        self.memory.save_state(self.run_state)
        self.memory.save_hypotheses(self.hypotheses)
        self.memory.save_facts(self.facts_doc)
        self.memory.save_artifacts(self.artifacts_doc)
        self.memory.save_dead_ends(self.dead_ends_doc)
        self.memory.save_candidates(self.candidates_doc)
        self.memory.save_overview(
            challenge_name=self.challenge_name,
            category=self.category,
            state=self.run_state,
            hypotheses=self.hypotheses,
            facts=self.facts_doc,
            artifacts=self.artifacts_doc,
            dead_ends=self.dead_ends_doc,
            candidates=self.candidates_doc,
        )

    def _sync_memory_from_evidence(self, source: str = "parser"):
        confirmed = self.facts_doc.setdefault("confirmed", [])
        ruled_out = self.facts_doc.setdefault("ruled_out", [])
        for text in self._evidence_confirmed[-20:]:
            self._append_memory_entry(confirmed, "text", text, source=source, step=int(self.step or 0))
        for text in self._evidence_ruled_out[-20:]:
            self._append_memory_entry(ruled_out, "text", text, source=source, step=int(self.step or 0))
        self.facts_doc["updated_at"] = utc_now_iso()

    def _fallback_hypotheses(self):
        cue = CATEGORY_EXECUTION_BRIEFS.get(self.category, "Classify the challenge and test the highest-signal path.")
        return [
            {
                "id": "h1",
                "title": "Classify the primary attack surface",
                "goal": cue,
                "next_action": "Use structured tools first and gather one high-signal fact.",
                "expected_signals": ["new artifact", "concrete error", "flag path"],
                "confidence": 0.6,
                "attempts": 0,
                "progress_events": 0,
                "failures": 0,
                "status": "open",
            },
            {
                "id": "h2",
                "title": "Exploit the most promising artifact or endpoint",
                "goal": "Take the strongest discovered lead and try one decisive action.",
                "next_action": "Use at most one short chain of tool calls to validate exploitation.",
                "expected_signals": ["state change", "decoded content", "credential or token"],
                "confidence": 0.45,
                "attempts": 0,
                "progress_events": 0,
                "failures": 0,
                "status": "open",
            },
        ]

    def _run_planner_phase(self, challenge_desc: str, recon: str, prior_summary: str | None = None, reason: str = ""):
        planner_system = (
            "You are the planning phase of a CTF harness. Produce only valid JSON with keys "
            "`summary`, `active_hypothesis_id`, and `hypotheses`. "
            "Each hypothesis must contain: id, title, goal, next_action, expected_signals, confidence. "
            "Prefer 2-4 hypotheses. Do not include answers. Do not guess flags."
        )
        overview = self.memory.load_all().get("overview", "")
        user_prompt = (
            f"Challenge:\n{challenge_desc}\n\n"
            f"Auto recon:\n{self._truncate_for_context(recon)}\n\n"
            f"Current evidence:\n{self._evidence_summary()}\n"
            f"Current overview:\n{overview[-2500:] if overview else '(none)'}\n"
            f"{('[PRIOR SUMMARY]\\n' + prior_summary + '\\n') if prior_summary else ''}"
            f"{('[REPLAN REASON]\\n' + reason + '\\n') if reason else ''}"
            "Return JSON only."
        )
        fallback = {
            "summary": "Using fallback planner because structured planning output was unavailable.",
            "active_hypothesis_id": "h1",
            "hypotheses": self._fallback_hypotheses(),
        }
        try:
            raw = self._complete_text([{"role": "user", "content": user_prompt}], system_prompt=planner_system, max_tokens=1600)
            payload = self._extract_json_payload(raw, fallback)
        except Exception as e:
            payload = deepcopy(fallback)
            payload["summary"] = f"Planner fallback used after error: {e}"
        hypotheses = []
        for idx, item in enumerate(payload.get("hypotheses") or []):
            if not isinstance(item, dict):
                continue
            hypotheses.append({
                "id": str(item.get("id") or f"h{idx + 1}"),
                "title": str(item.get("title") or f"Hypothesis {idx + 1}").strip(),
                "goal": str(item.get("goal") or "").strip(),
                "next_action": str(item.get("next_action") or "").strip(),
                "expected_signals": [str(x).strip() for x in (item.get("expected_signals") or []) if str(x).strip()],
                "confidence": float(item.get("confidence") or 0.0),
                "attempts": int(item.get("attempts") or 0),
                "progress_events": int(item.get("progress_events") or 0),
                "failures": int(item.get("failures") or 0),
                "status": str(item.get("status") or "open").strip() or "open",
            })
        if not hypotheses:
            hypotheses = self._fallback_hypotheses()
        active_id = str(payload.get("active_hypothesis_id") or hypotheses[0]["id"])
        if active_id not in {h["id"] for h in hypotheses}:
            active_id = hypotheses[0]["id"]
        self.hypotheses = hypotheses
        self.run_state.update({
            "phase": "planner",
            "active_hypothesis_id": active_id,
            "planner_summary": str(payload.get("summary") or "").strip(),
        })
        self._needs_replan = False
        self.emit("plan", {"text": self.run_state["planner_summary"] or "Planner updated hypotheses.", "replan": bool(reason)})
        self._trace_loop("planner_complete", hypothesis_count=len(self.hypotheses), active_hypothesis_id=active_id)
        self._save_memory_documents()

    def _hypothesis_score(self, hypothesis: dict) -> float:
        return (
            float(hypothesis.get("confidence") or 0.0)
            + (0.15 * float(hypothesis.get("progress_events") or 0))
            - (0.2 * float(hypothesis.get("failures") or 0))
            - (0.05 * float(hypothesis.get("attempts") or 0))
        )

    def _select_active_hypothesis(self) -> dict | None:
        open_items = [h for h in self.hypotheses if str(h.get("status") or "open") in {"open", "active"}]
        if not open_items:
            return None
        best = sorted(open_items, key=self._hypothesis_score, reverse=True)[0]
        for item in self.hypotheses:
            item["status"] = "active" if item.get("id") == best.get("id") else ("open" if item.get("status") != "exhausted" else "exhausted")
        self.run_state["active_hypothesis_id"] = best.get("id")
        self._active_hypothesis = best
        self._next_hypothesis = best.get("title") or ""
        return best

    def _build_execution_prompt(self, challenge_desc: str, recon: str, hypothesis: dict) -> str:
        confirmed = [item.get("text") if isinstance(item, dict) else str(item) for item in (self.facts_doc.get("confirmed") or [])][-8:]
        ruled_out = [item.get("text") if isinstance(item, dict) else str(item) for item in (self.facts_doc.get("ruled_out") or [])][-6:]
        artifacts = [item.get("label") or item.get("path") or item.get("text") for item in self.artifacts_doc[-6:]]
        tooling_ctx = ""
        if self._preflight_missing_tools:
            tooling_ctx = (
                "\nUnavailable tools: " + ", ".join(self._preflight_missing_tools)
                + ". Do not plan around them."
            )
        return (
            f"Challenge:\n{challenge_desc}\n\n"
            f"Auto recon:\n{self._truncate_for_context(recon)}\n\n"
            f"Active hypothesis:\n"
            f"- title: {hypothesis.get('title')}\n"
            f"- goal: {hypothesis.get('goal')}\n"
            f"- next_action: {hypothesis.get('next_action')}\n"
            f"- expected_signals: {', '.join(hypothesis.get('expected_signals') or []) or 'none'}\n\n"
            f"Confirmed facts:\n- " + ("\n- ".join(confirmed) if confirmed else "none yet") + "\n\n"
            f"Ruled out:\n- " + ("\n- ".join(ruled_out) if ruled_out else "none yet") + "\n\n"
            f"Recent artifacts:\n- " + ("\n- ".join([a for a in artifacts if a]) if artifacts else "none yet") + "\n"
            f"{tooling_ctx}\n\n"
            "Execution policy:\n"
            f"- Use between 1 and {self.max_tool_calls_per_turn} decisive tool calls.\n"
            "- Do not ask for approval.\n"
            "- Prefer structured tools before raw shell.\n"
            "- Only act on the current hypothesis unless a tool result forces a pivot.\n"
            "- Do not guess answers or flags.\n"
            "Execute now."
        )

    def _execute_tool_batch(self, msg) -> dict:
        self.messages.append({
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": msg.tool_calls_raw or [],
        })
        step_had_error = False
        step_had_progress = False
        submitted = False
        tool_results = []
        for idx, tc in enumerate(msg.tool_calls or []):
            fn = tc.function.name
            self._trace_loop("tool_dispatch_start", tool=fn, index=int(idx))
            if idx >= self.max_tool_calls_per_turn:
                step_had_error = True
                tool_results.append({"tool": fn, "result": f"[tool error] too many tool calls (limit {self.max_tool_calls_per_turn})", "error": True, "progress": False})
                continue
            args, arg_err = self._parse_tool_args(tc.function.arguments)
            if arg_err:
                result = f"[tool error] invalid arguments for {fn}: {arg_err}"
                self.emit("error", {"message": f"Tool args error ({fn}): {arg_err}"})
                self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                tool_results.append({"tool": fn, "result": result, "error": True, "progress": False})
                step_had_error = True
                continue
            try:
                result = self._dispatch(fn, args)
            except Exception as e:
                result = f"[tool error] {e}"
                self.emit("error", {"message": f"Tool error ({fn}): {e}"})
                step_had_error = True
            error = bool(self._is_error_result(result))
            progress = bool(self._last_tool_progress)
            if error:
                step_had_error = True
            if progress:
                step_had_progress = True
            self._trace_loop("tool_dispatch_end", tool=fn, error=error, progress=progress)
            compact = self._compact_tool_result_for_context(result)
            self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": compact})
            tool_results.append({"tool": fn, "result": str(result or ""), "error": error, "progress": progress})
            chal = get_challenge(self.cid) or {}
            if fn == "submit_flag" or chal.get("status") == "pending_approval":
                submitted = True
            if submitted or not self.running:
                break
        return {
            "tool_results": tool_results,
            "had_error": step_had_error,
            "had_progress": step_had_progress,
            "submitted": submitted,
        }

    def _run_executor_phase(self, challenge_desc: str, recon: str, hypothesis: dict) -> dict:
        self.run_state["phase"] = "executor"
        self.messages = [{"role": "user", "content": self._build_execution_prompt(challenge_desc, recon, hypothesis)}]
        msg = None
        last_error = ""
        for attempt in range(2):
            try:
                msg = self._call()
            except Exception as e:
                last_error = str(e)
                break
            self._trace_loop("step_model_response", has_content=bool(msg.content), tool_call_count=len(msg.tool_calls or []))
            if msg.content:
                self.emit("thought", {"text": msg.content, "type": "reasoning"})
            if msg.tool_calls:
                break
            self.messages.append({"role": "assistant", "content": msg.content or ""})
            self.messages.append({
                "role": "user",
                "content": f"Use between 1 and {self.max_tool_calls_per_turn} tool calls now. No prose-only response.",
            })
        if last_error:
            return {
                "assistant_text": "",
                "tool_results": [],
                "had_error": True,
                "had_progress": False,
                "combined_output": f"[api error] {last_error}",
                "candidate_flags": [],
            }
        if not msg or not msg.tool_calls:
            text = msg.content if msg else "No model response."
            return {
                "assistant_text": text or "",
                "tool_results": [],
                "had_error": True,
                "had_progress": False,
                "combined_output": text or "[error] no tool calls produced",
                "candidate_flags": self._extract_flag_candidates(text or ""),
            }
        batch = self._execute_tool_batch(msg)
        combined_output = "\n\n".join(result["result"] for result in batch["tool_results"] if result.get("result"))
        return {
            "assistant_text": msg.content or "",
            "tool_results": batch["tool_results"],
            "had_error": batch["had_error"],
            "had_progress": batch["had_progress"],
            "combined_output": combined_output,
            "candidate_flags": self._extract_flag_candidates(combined_output),
            "submitted": batch["submitted"],
        }

    def _run_verifier_phase(self, hypothesis: dict, step_result: dict) -> dict:
        fallback = {
            "verdict": "progress" if step_result.get("had_progress") else ("error" if step_result.get("had_error") else "no_progress"),
            "summary": "Execution produced useful signal." if step_result.get("had_progress") else "Execution did not produce enough new signal.",
            "new_facts": [],
            "ruled_out": [],
            "artifacts": [],
            "candidate_flags": step_result.get("candidate_flags") or [],
            "should_replan": False,
            "switch_hypothesis": bool(step_result.get("had_error")),
            "next_action": hypothesis.get("next_action") or "",
            "confidence": 0.7 if step_result.get("had_progress") else 0.25,
        }
        verifier_system = (
            "You are the verifier phase of a CTF harness. Return only JSON with keys "
            "`verdict`, `summary`, `new_facts`, `ruled_out`, `artifacts`, `candidate_flags`, "
            "`should_replan`, `switch_hypothesis`, `next_action`, `confidence`. "
            "Verdict must be one of progress, no_progress, dead_end, candidate, error."
        )
        tool_summary = "\n".join(
            f"- {item.get('tool')}: {'error' if item.get('error') else 'ok'} | {self._truncate_for_context(item.get('result') or '')}"
            for item in (step_result.get("tool_results") or [])
        )
        verifier_prompt = (
            f"Active hypothesis:\n{json.dumps(hypothesis, indent=2)}\n\n"
            f"Evidence summary:\n{self._evidence_summary()}\n\n"
            f"Tool results:\n{tool_summary or '(none)'}\n\n"
            "Return JSON only."
        )
        try:
            raw = self._complete_text([{"role": "user", "content": verifier_prompt}], system_prompt=verifier_system, max_tokens=1200)
            verdict = self._extract_json_payload(raw, fallback)
        except Exception as e:
            verdict = deepcopy(fallback)
            verdict["summary"] = f"Verifier fallback used after error: {e}"
        self.emit("thought", {"text": f"Verifier: {verdict.get('summary') or 'No summary.'}", "type": "system"})
        self.run_state["phase"] = "verifier"
        self.run_state["verifier_summary"] = str(verdict.get("summary") or "").strip()
        return verdict

    def _commit_step_verdict(self, hypothesis: dict, step_result: dict, verdict: dict):
        self.run_state["phase"] = "memory_commit"
        self.run_state["last_tool_summary"] = self._truncate_for_context(step_result.get("combined_output") or "")
        self._sync_memory_from_evidence(source="tool_output")

        for text in verdict.get("new_facts") or []:
            self._append_memory_entry(self.facts_doc.setdefault("confirmed", []), "text", text, source="verifier", step=int(self.step or 0))
        for text in verdict.get("ruled_out") or []:
            self._append_memory_entry(self.facts_doc.setdefault("ruled_out", []), "text", text, source="verifier", step=int(self.step or 0))
        for item in verdict.get("artifacts") or []:
            if isinstance(item, dict):
                label = item.get("label") or item.get("path") or item.get("text")
                self._append_memory_entry(self.artifacts_doc, "label", label, path=item.get("path"), note=item.get("note"), step=int(self.step or 0))
            else:
                self._append_memory_entry(self.artifacts_doc, "label", str(item), step=int(self.step or 0))
        for flag in (verdict.get("candidate_flags") or []) + (step_result.get("candidate_flags") or []):
            if self._append_memory_entry(self.candidates_doc.setdefault("flags", []), "value", flag, status="candidate", source="verifier", step=int(self.step or 0)):
                self._append_memory_entry(self.facts_doc.setdefault("flag_candidates", []), "value", flag, source="verifier", step=int(self.step or 0))

        hypothesis["attempts"] = int(hypothesis.get("attempts") or 0) + 1
        if verdict.get("verdict") in {"progress", "candidate"}:
            hypothesis["progress_events"] = int(hypothesis.get("progress_events") or 0) + 1
            hypothesis["failures"] = 0
        else:
            hypothesis["failures"] = int(hypothesis.get("failures") or 0) + 1
        if verdict.get("next_action"):
            hypothesis["next_action"] = str(verdict.get("next_action") or "").strip()
        hypothesis["confidence"] = float(verdict.get("confidence") or hypothesis.get("confidence") or 0.0)

        should_exhaust = verdict.get("verdict") == "dead_end" or int(hypothesis.get("failures") or 0) >= 2
        if should_exhaust:
            hypothesis["status"] = "exhausted"
            self._append_memory_entry(
                self.dead_ends_doc,
                "title",
                hypothesis.get("title") or "Hypothesis exhausted",
                text=str(verdict.get("summary") or "").strip(),
                step=int(self.step or 0),
            )
        else:
            hypothesis["status"] = "active"
        self._needs_replan = bool(verdict.get("should_replan")) or not any(
            str(item.get("status") or "open") in {"open", "active"} for item in self.hypotheses
        )
        self.run_state["status"] = "running" if self.running else "stopped"
        self._save_memory_documents()

    def _checkpoint_state(self, status: str, phase: str, summary: str = ""):
        self.run_state.update({
            "status": status,
            "phase": phase,
            "step": int(self.step or 0),
        })
        if summary:
            self.run_state["verifier_summary"] = summary
        self._save_memory_documents()
        self._save_retry_summary()

    def _run(self, challenge_desc, prior_summary):
        self._trace_loop("run_start", category=self.category, model=self.model)
        if self._pre_llm_short_circuit():
            self._trace_loop("run_exit_short_circuit", provider=self.provider)
            return
        self._load_memory_documents()
        self.run_state.update({
            "status": "running",
            "phase": "session_start",
            "run_id": uuid.uuid4().hex[:12],
        })
        recon = self.container.run("ls -la /ctf/ && echo '---' && file /ctf/* 2>/dev/null")
        self.emit("output", {"text": f"[auto-recon]\n{recon}"})
        self._update_evidence_from_output("auto-recon", recon)
        self._ensure_tooling_ready()
        self._sync_memory_from_evidence(source="auto-recon")
        self._save_memory_documents()

        max_steps = STEP_LIMITS.get(self.category, 40)
        for idx in range(max_steps):
            self.step = idx + 1
            self.run_state["step"] = self.step
            if not self.running:
                self._trace_loop("run_stopped", reason="running_false")
                self._checkpoint_state("stopped", "stop", "Run stopped by user.")
                return
            if self._needs_replan or not self.hypotheses:
                self._run_planner_phase(challenge_desc, recon, prior_summary=prior_summary, reason="Need fresh hypotheses." if idx else "")
            hypothesis = self._select_active_hypothesis()
            if not hypothesis:
                self._needs_replan = True
                continue
            self._trace_loop("step_start", step=int(self.step), active_hypothesis_id=hypothesis.get("id"))
            step_result = self._run_executor_phase(challenge_desc, recon, hypothesis)
            if step_result.get("assistant_text") and _is_approval_seeking_text(step_result.get("assistant_text")):
                self.emit("thought", {"text": "Harness ignored approval-seeking text and continued autonomous execution.", "type": "system"})
            if step_result.get("submitted") and not self.running:
                self._checkpoint_state("pending_approval", "done", "Flag candidate queued for approval.")
                return
            if not self.running:
                self._checkpoint_state("stopped", "stop", "Run stopped by user.")
                return
            verdict = self._run_verifier_phase(hypothesis, step_result)
            self._commit_step_verdict(hypothesis, step_result, verdict)
            self._trace_loop(
                "step_end",
                progress=bool(step_result.get("had_progress")),
                error=bool(step_result.get("had_error")),
                verdict=str(verdict.get("verdict") or ""),
            )
            if not self.running:
                self._checkpoint_state("pending_approval", "done", "Flag candidate queued for approval.")
                return

        if self.running:
            self.running = False
            self._checkpoint_state("unsolved", "max_steps", "Max steps reached without solving the challenge.")
            update_challenge(self.cid, status="unsolved")
            self.emit("done", {"status": "unsolved", "message": "Max steps reached without finding the flag."})
            self._trace_loop("run_exit_max_steps", max_steps=int(max_steps))

    def _dispatch(self, fn, args):
        if fn == "run_command":
            cmd      = args["command"]
            reason   = args.get("reasoning") or "Running command."
            timeout  = 120 if args.get("long_running") else 60
            normalized_cmd = self._normalize_command(cmd)
            family = self._command_family(normalized_cmd)
            hypothesis_key = self._hypothesis_key(reason, family, normalized_cmd)
            self._trace_loop(
                "run_command_enter",
                family=family,
                hypothesis_key=hypothesis_key[:80],
                timeout=int(timeout),
            )
            if not args.get("long_running") and not args.get("allow_repeat") and self._is_repeated_command(normalized_cmd):
                self.emit("thought", {"text": f"Blocked repeated command with no new signal: {normalized_cmd}", "type": "system"})
                self._last_tool_progress = False
                self._trace_loop("run_command_blocked", reason="repeated_command", family=family)
                return f"[error] blocked repeated command: {normalized_cmd}"
            hypothesis_budget = self.hypothesis_budget
            if self.category == "web":
                hypothesis_budget = min(hypothesis_budget, 1)
            if not args.get("long_running") and self._hypothesis_no_progress.get(hypothesis_key, 0) >= hypothesis_budget:
                self.emit("thought", {
                    "text": f"Hypothesis budget exceeded for '{hypothesis_key[:40]}'. Pivot required.",
                    "type": "system",
                })
                self._next_hypothesis = "Choose a different hypothesis class with a different command family."
                self._last_tool_progress = False
                self._trace_loop("run_command_blocked", reason="hypothesis_budget", family=family)
                return f"[error] hypothesis budget exceeded: {hypothesis_key}"
            family_budget = int(self.cfg.get("family_budget_non_web") or 4)
            if self.category == "web":
                family_budget = int(self.cfg.get("family_budget_web") or 1)
            if (
                not args.get("long_running")
                and not self._is_family_block_exempt(family)
                and self._family_no_progress.get(family, 0) >= family_budget
            ):
                self.emit("thought", {"text": f"Blocked low-yield command family '{family}'. Try a different strategy.", "type": "system"})
                self._last_tool_progress = False
                self._trace_loop("run_command_blocked", reason="family_budget", family=family)
                return f"[error] blocked low-yield command family: {family}"
            self.emit("thought", {"text": reason, "type": "reasoning"})
            python_cmd = re.match(r"^\s*python(3(\.\d+)*)?\b", cmd) is not None
            # Preflight: if running a python script, ensure imports are installed in /ctf/.venv
            m = re.match(r"^\s*python(3(\.\d+)*)?\s+([^\s]+\.py)\b", cmd)
            if m and self.allow_runtime_installs:
                script = m.group(3)
                qscript = _shell_quote(script)
                self.container.run("python3 -m venv /ctf/.venv || true")
                check = self.container.run(
                    "/ctf/.venv/bin/python - "
                    + qscript +
                    " <<'PY'\n"
                    "import ast, sys, importlib.util\n"
                    "path = sys.argv[1]\n"
                    "tree = ast.parse(open(path,'rb').read(), filename=path)\n"
                    "mods = []\n"
                    "for node in ast.walk(tree):\n"
                    "    if isinstance(node, ast.Import):\n"
                    "        for n in node.names:\n"
                    "            mods.append(n.name.split('.')[0])\n"
                    "    elif isinstance(node, ast.ImportFrom):\n"
                    "        if node.module:\n"
                    "            mods.append(node.module.split('.')[0])\n"
                    "missing = []\n"
                    "seen = set()\n"
                    "for mod in mods:\n"
                    "    if mod in seen:\n"
                    "        continue\n"
                    "    seen.add(mod)\n"
                    "    if importlib.util.find_spec(mod) is None:\n"
                    "        missing.append(mod)\n"
                    "print('\\n'.join(missing))\n"
                    "PY"
                )
                missing_mods = [ln.strip() for ln in (check or '').splitlines() if ln.strip()]
                if missing_mods:
                    pkgs = [_infer_pip_package(mn) for mn in missing_mods]
                    self.emit("thought", {"text": f"Preflight: installing Python deps in /ctf/.venv: {', '.join(pkgs)}", "type": "system"})
                    self.container.run("/ctf/.venv/bin/python -m pip -q install --upgrade pip || true")
                    self.container.run(f"/ctf/.venv/bin/python -m pip -q install {' '.join(pkgs)} || true")
            cmd_to_run = cmd
            if python_cmd:
                self.container.run("python3 -m venv /ctf/.venv || true")
                cmd_to_run = re.sub(r"^\s*python(3(\.\d+)*)?\b", "/ctf/.venv/bin/python", cmd, count=1)
            # Binwalk extraction requires explicit run user in current versions.
            if re.match(r"^\s*binwalk\b", cmd_to_run) and "--run-as=" not in cmd_to_run:
                cmd_to_run = re.sub(r"^\s*binwalk\b", "binwalk --run-as=root", cmd_to_run, count=1)

            self.emit("command", {"cmd": cmd})
            self._record_command(normalized_cmd)
            out = self.container.run(cmd_to_run, timeout=timeout)
            missing_cmd = self._extract_missing_command(out or "")
            if missing_cmd:
                out_retry = self._maybe_install_and_retry_missing_tool(missing_cmd, cmd_to_run, timeout)
                if out_retry:
                    out = out_retry
            # Auto-fix missing Python modules by installing in a venv and retrying once.
            missing = re.search(r"No module named ['\"]([^'\"]+)['\"]", out or "")
            if missing and self.allow_runtime_installs:
                mod = missing.group(1)
                pkg = _infer_pip_package(mod)
                if pkg:
                    self.emit("thought", {"text": f"Missing Python module '{mod}'. Installing '{pkg}' in /ctf/.venv and retrying…", "type": "system"})
                    self.container.run("python3 -m venv /ctf/.venv || true")
                    self.container.run("/ctf/.venv/bin/python -m pip -q install --upgrade pip || true")
                    self.container.run(f"/ctf/.venv/bin/python -m pip -q install {pkg} || true")
                    # Re-run using the venv python via PATH
                    rerun = re.sub(r"^\s*python(3(\.\d+)*)?\b", "/ctf/.venv/bin/python", cmd, count=1)
                    self.emit("command", {"cmd": rerun})
                    out2 = self.container.run(rerun, timeout=timeout)
                    if out2:
                        out = out2
            self.emit("output", {"text": out})
            self._update_evidence_from_output(cmd, out)
            self._last_cmd_status[normalized_cmd] = {"error": self._is_error_result(out)}
            if self._maybe_auto_submit_from_output(out, source=f"run_command: {cmd}"):
                self._last_tool_progress = True
                self._trace_loop("run_command_exit", auto_submit=True, progress=True, family=family)
                return f"Flag auto-submitted from output."
            hint_progress = self._try_hint_actions()
            progress = self._score_progress(out)
            if hint_progress:
                progress = True
            self._last_tool_progress = progress
            if progress:
                self._family_no_progress[family] = 0
                self._hypothesis_no_progress[hypothesis_key] = 0
                self._next_hypothesis = ""
            else:
                self._family_no_progress[family] = self._family_no_progress.get(family, 0) + 1
                self._hypothesis_no_progress[hypothesis_key] = self._hypothesis_no_progress.get(hypothesis_key, 0) + 1
                if self._hypothesis_no_progress[hypothesis_key] >= self.hypothesis_budget:
                    self._add_evidence("ruled_out", f"Hypothesis exhausted: {hypothesis_key[:80]}")
                    self._next_hypothesis = "Switch to a new hypothesis and different command family."
            # Emit error event for dashboard if output shows a failure
            if out and re.search(r"Traceback|ModuleNotFoundError|No such file or directory|command not found|\berror:", out, re.IGNORECASE):
                first = out.strip().splitlines()[0] if out.strip() else "Command error"
                self.emit("error", {"message": first, "cmd": cmd})
            self._trace_loop(
                "run_command_exit",
                progress=bool(self._last_tool_progress),
                family=family,
                hypothesis_no_progress=int(self._hypothesis_no_progress.get(hypothesis_key, 0)),
                family_no_progress=int(self._family_no_progress.get(family, 0)),
            )
            return self._truncate_for_context(out)

        elif fn == "run_gdb":
            binary = args["binary_path"]
            cmds   = args["gdb_commands"]
            label  = f"gdb {binary} [{', '.join(cmds[:2])}{'…' if len(cmds)>2 else ''}]"
            self.emit("command", {"cmd": label, "gdb": True})
            out = self.container.run_gdb(binary, cmds)
            self.emit("output", {"text": out})
            self._update_evidence_from_output(label, out)
            if self._maybe_auto_submit_from_output(out, source=f"run_gdb: {binary}"):
                self._last_tool_progress = True
                return f"Flag auto-submitted from output."
            hint_progress = self._try_hint_actions()
            self._last_tool_progress = self._score_progress(out)
            if hint_progress:
                self._last_tool_progress = True
            return self._truncate_for_context(out)

        elif fn == "write_file":
            fname   = args.get("filename", "").lstrip("/").replace("../", "").strip()
            content = args.get("content", "")
            reason  = args.get("reasoning") or "Writing file for the next step."
            if not fname:
                self._last_tool_progress = False
                return "[error] filename is required"
            self.emit("thought", {"text": reason, "type": "reasoning"})
            self.emit("command", {"cmd": f"write_file: {fname}"})
            try:
                remote_path = self.container.write_file(fname, content)
                # Make scripts executable
                if fname.endswith((".py", ".sh", ".rb", ".pl")):
                    self.container.run(f"chmod +x {remote_path}")
                out = f"Written {len(content.encode())} bytes to {remote_path}"
                self.emit("output", {"text": out})
                self._last_tool_progress = True
                return out
            except Exception as e:
                err = f"[tool error] write_file failed: {e}"
                self.emit("error", {"message": str(e)})
                self._last_tool_progress = False
                return err

        elif fn == "list_files":
            return self._tool_list_files(args)

        elif fn == "save_note":
            return self._tool_save_note(args)

        elif fn == "extract_artifact":
            return self._tool_extract_artifact(args)

        elif fn == "http_request":
            return self._tool_http_request(args)

        elif fn == "search_flag":
            pattern = args.get("flag_pattern", "").strip() or self.flag_format or "flag{"
            qpat = _shell_quote(pattern)
            cmd = (
                f"grep -r --include='*' -E {qpat} /ctf/ 2>/dev/null | head -50; "
                "ec=$?; "
                f"if [ $ec -eq 2 ]; then grep -r --include='*' -F {qpat} /ctf/ 2>/dev/null | head -50; fi"
            )
            self.emit("command", {"cmd": f"search_flag: {pattern}"})
            out = self.container.run(cmd, timeout=60)
            self.emit("output", {"text": out})
            self._update_evidence_from_output(f"search_flag: {pattern}", out)
            if self._maybe_auto_submit_from_output(out, source=f"search_flag: {pattern}"):
                self._last_tool_progress = True
                return f"Flag auto-submitted from output."
            hint_progress = self._try_hint_actions()
            self._last_tool_progress = self._score_progress(out)
            if hint_progress:
                self._last_tool_progress = True
            return self._truncate_for_context(out)

        elif fn == "submit_flag":
            flag = args["flag"]
            how  = args.get("how_found", "")
            # Manual submit guardrail: if no explicit flag_format is configured, only accept
            # canonical flag-shaped tokens unless override is enabled.
            if self.flag_format:
                if not self._flag_matches_format(flag):
                    msg = f"Submitted flag does not match expected format '{self.flag_format}'. Keep searching."
                    self.emit("error", {"message": msg, "flag": flag})
                    self._last_tool_progress = False
                    return f"[error] {msg}"
            else:
                from utils import _is_plausible_flag_token
                flag_ok = _is_plausible_flag_token(flag) and not self._is_likely_system_flag_artifact(flag, how or "")
                if not flag_ok and not self._allows_noncanonical_submit(flag, how):
                    msg = (
                        "Submitted value is not a canonical flag token (e.g. word{...}). "
                        "Set challenge flag format if this target uses a non-standard answer."
                    )
                    self.emit("error", {"message": msg, "flag": flag})
                    self._last_tool_progress = False
                    return f"[error] {msg}"
            if self._finalize_flag_candidate(flag, how=how, source="submit_flag"):
                self._last_tool_progress = True
                return f"Flag candidate queued for approval: {flag}"
            self._last_tool_progress = False
            return "[error] empty flag candidate"

        self._last_tool_progress = False
        return f"Unknown: {fn}"
