"""
CTFAgentCore — base class with __init__, run loop, dispatch, and helpers.
"""
import ast
import json
import os
import re
import threading
import time
import uuid
from collections import deque
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
from db import update_challenge
from agent.registry import _log_event


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
        self.messages= []
        self.running = False
        self.step    = 0
        self.total_in= 0
        self.total_out=0
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
        self._running_hint_action = False
        self._last_cmd_status = {}   # cmd -> {"error": bool}
        self._preflight_missing_tools = []
        self._evidence_confirmed = []
        self._evidence_ruled_out = []
        self._next_hypothesis = ""
        self._evidence_version = 0
        self._hypothesis_no_progress = {}
        self._flag_evidence = {}
        self._answer_candidates = set()
        self._answer_mode = self._is_answer_style_challenge()

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
        self.running = False
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
        if not self.openai_client:
            return
        try:
            summary_model = "gpt-4o-mini"
            r = self.openai_client.chat.completions.create(
                model=summary_model, **self._token_limit_kw(500, model_name=summary_model),
                messages=[{"role": "user", "content":
                    "Summarize this FAILED CTF attempt for a retry: files, tried, failed, unexplored, next approach.\n\n"
                    + json.dumps(self.messages[-20:], indent=2)}]
            )
            update_challenge(self.cid, retry_summary=r.choices[0].message.content)
        except Exception:
            pass

    def _run(self, challenge_desc, prior_summary):
        # Auto recon
        self._trace_loop("run_start", category=self.category, model=self.model)
        recon = self.container.run("ls -la /ctf/ && echo '---' && file /ctf/* 2>/dev/null")
        self.emit("output", {"text": f"[auto-recon]\n{recon}"})
        self._update_evidence_from_output("auto-recon", recon)
        self._ensure_tooling_ready()
        if self._run_forensics_fastpath(recon):
            self._trace_loop("run_exit_fastpath", reason="forensics_fastpath")
            return
        rev_fast_ctx = self._run_rev_qna_fastpath(recon, challenge_desc)

        prior_ctx = f"\n\n[PRIOR ATTEMPT]\n{prior_summary}" if prior_summary else ""
        tooling_ctx = ""
        if self._preflight_missing_tools:
            tooling_ctx = (
                "\n\n[TOOLING CONSTRAINT]\nRuntime installs are disabled. "
                "The following tools are currently unavailable and must not be used in the plan: "
                + ", ".join(self._preflight_missing_tools)
                + ". Use alternatives that are already installed."
            )
        playbook_ctx = self._forensics_playbook_hint(recon)
        web_ctx = ""
        if self.category == "web":
            web_ctx = (
                "\n[MANDATORY WEB DECISION TREE]\n"
                "1) Upload primitive validation.\n"
                "2) Execution path check.\n"
                "3) Include/LFI checks on high-probability params.\n"
                "4) Bounded endpoint fuzzing only after 1-3 fail.\n"
                "Repeated default 404/403 or same-body responses are non-progress.\n"
            )
        initial = (
            f"{challenge_desc}\n\nFiles in container:\n{recon}{prior_ctx}{tooling_ctx}{playbook_ctx}{web_ctx}{rev_fast_ctx}\n\n"
            f"{self._evidence_summary()}\n"
            "Execution policy:\n"
            "- Use exactly one decisive tool call per turn.\n"
            "- Do not ask for approval; execute autonomously.\n"
            "- Prefer proving or falsifying a hypothesis in one action.\n"
            "- If a hypothesis fails twice, pivot to a different hypothesis class.\n"
            "- For WEB category, strictly follow: upload validation -> execution path -> include/LFI -> bounded fuzzing.\n"
            "Now execute the best next action with one tool call."
        )
        self.messages.append({"role": "user", "content": initial})

        max_steps = STEP_LIMITS.get(self.category, 40)
        consecutive_errors = 0
        last_evidence_version = self._evidence_version
        for self.step in range(max_steps):
            if not self.running:
                self._trace_loop("run_stopped", reason="running_false")
                break

            if self.step > 0 and self.step % 15 == 0:
                self._summarize()

            self._trace_loop(
                "step_start",
                evidence_version=int(self._evidence_version),
                no_progress_steps=int(self._no_progress_steps),
                consecutive_errors=int(consecutive_errors),
            )
            try:
                msg = self._call()
            except Exception as e:
                self.emit("thought", {"text": f"API error: {e}", "type": "error"})
                self.emit("error", {"message": f"API error: {e}"})
                self._prune_dangling_tool_calls()
                self._trace_loop("step_api_error", error=str(e))
                break

            self._trace_loop(
                "step_model_response",
                has_content=bool(msg.content),
                tool_call_count=len(msg.tool_calls or []),
            )
            if msg.content:
                self.emit("thought", {"text": msg.content, "type": "reasoning"})
                if _is_approval_seeking_text(msg.content):
                    self.messages.append({"role": "assistant", "content": msg.content or ""})
                    self.messages.append({"role": "user", "content":
                        "Do not ask for approval. Choose the best next decisive action and execute it now with one tool call."
                    })
                    continue

            if not msg.tool_calls:
                self.messages.append({"role": "assistant", "content": msg.content or ""})
                self.messages.append({"role": "user", "content":
                    "Use exactly one decisive tool call now. No additional planning text."
                })
                self._trace_loop("step_no_tool_calls")
                continue

            self.messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": msg.tool_calls_raw or [],
            })

            step_had_error = False
            step_had_progress = False
            for idx, tc in enumerate(msg.tool_calls):
                fn   = tc.function.name
                self._trace_loop("tool_dispatch_start", tool=fn, index=int(idx))
                if idx > 0:
                    step_had_error = True
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": "[tool error] Only one tool call is allowed per turn. Re-issue with a single decisive tool call.",
                    })
                    continue
                args, arg_err = self._parse_tool_args(tc.function.arguments)
                if arg_err:
                    self.emit("error", {"message": f"Tool args error ({fn}): {arg_err}"})
                    self.messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": f"[tool error] invalid arguments for {fn}: {arg_err}",
                    })
                    # Defer user correction until AFTER all tool responses in this batch.
                    self._pending_directive_messages.append({"role": "user", "content":
                        f"Your tool call for '{fn}' had invalid/missing JSON arguments. "
                        f"Re-issue the tool call with valid JSON that matches the schema."
                    })
                    step_had_error = True
                    continue
                try:
                    result = self._dispatch(fn, args)
                except Exception as e:
                    result = f"[tool error] {e}"
                    self.emit("error", {"message": f"Tool error ({fn}): {e}"})
                    step_had_error = True
                if self._is_error_result(result):
                    step_had_error = True
                if self._last_tool_progress:
                    step_had_progress = True
                self._trace_loop(
                    "tool_dispatch_end",
                    tool=fn,
                    error=bool(self._is_error_result(result)),
                    progress=bool(self._last_tool_progress),
                )
                self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": result})
                if fn == "submit_flag":
                    self._trace_loop("run_exit_submit_flag")
                    return
                if not self.running:
                    self._trace_loop("run_exit_not_running")
                    return
            # ── Flush deferred directive messages ─────────────────────────────────
            # _inject_directive() queues messages here instead of writing directly to
            # self.messages during dispatch, to preserve the required message ordering:
            #   assistant {tool_calls} → tool {response} → [user directives here]
            if self._pending_directive_messages:
                for dm in self._pending_directive_messages:
                    self.messages.append(dm)
                self._pending_directive_messages.clear()

            consecutive_errors = consecutive_errors + 1 if step_had_error else 0
            self._no_progress_steps = 0 if step_had_progress else (self._no_progress_steps + 1)
            evidence_changed = self._evidence_version != last_evidence_version
            if evidence_changed:
                last_evidence_version = self._evidence_version
            if self._no_progress_steps >= 2 or consecutive_errors >= 2:
                self.emit("thought", {"text": "Low information gain across recent steps. Forcing strategy shift.", "type": "system"})
                self.messages.append({"role": "user", "content":
                    self._evidence_summary()
                    + "You are stuck. Pick a NEW hypothesis class and run one decisive tool call to falsify/confirm it. "
                      "Do not repeat previous command families."
                })
                self._trace_loop(
                    "step_forced_shift",
                    no_progress_steps=int(self._no_progress_steps),
                    consecutive_errors=int(consecutive_errors),
                )
                self._no_progress_steps = 0
                consecutive_errors = 0
            elif evidence_changed:
                self.messages.append({"role": "user", "content":
                    self._evidence_summary()
                    + "Evidence changed. Choose the single best next action."
                })
                self._trace_loop("step_evidence_changed", evidence_version=int(self._evidence_version))
            else:
                self._trace_loop(
                    "step_end",
                    progress=bool(step_had_progress),
                    error=bool(step_had_error),
                    no_progress_steps=int(self._no_progress_steps),
                )

        if self.running:
            self.emit("done", {"status": "unsolved", "message": "Max steps reached without finding the flag."})
            self._save_retry_summary()
            update_challenge(self.cid, status="unsolved")
            self._trace_loop("run_exit_max_steps", max_steps=int(max_steps))
        self.running = False

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
