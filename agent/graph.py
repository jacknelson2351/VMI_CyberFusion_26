"""
LangGraph workflow for the CTF solver.

This file intentionally contains only control flow. The actual tools, evidence,
flag checks, and model adapters stay on the CTFAgent instance.
"""
from __future__ import annotations

from typing import Literal, TypedDict

from db import get_challenge

try:
    from langgraph.graph import END, START, StateGraph
except Exception:  # pragma: no cover - handled at runtime
    END = START = StateGraph = None


class SolverState(TypedDict, total=False):
    messages: list[dict]
    pending_tool_calls: list[dict]
    rounds: int
    submitted: bool
    last_progress: bool
    stop_reason: str
    nudges: int


def run_solver_graph(agent, initial_messages: list[dict], max_steps: int, start_round: int = 0) -> SolverState:
    if StateGraph is None:
        raise RuntimeError("LangGraph is not installed. Run: pip install -r requirements.txt")

    def call_model(state: SolverState) -> SolverState:
        rounds = int(state.get("rounds") or 0)
        if rounds >= max_steps:
            return {**state, "pending_tool_calls": [], "stop_reason": "max_steps"}
        if not agent.running:
            return {**state, "pending_tool_calls": [], "stop_reason": "stopped"}

        agent.step = rounds + 1
        if agent.memory:
            agent.memory.step = agent.step
        agent.messages = list(state.get("messages") or [])
        if hasattr(agent, "_apply_pending_user_messages"):
            agent._apply_pending_user_messages()
        agent._prepare_step()
        if len(agent.messages) > 18 or (agent._should_compress_context() and len(agent.messages) > 8):
            agent._summarize()

        agent._trace_loop(
            "step_start",
            framework="langgraph",
            agent_phase=getattr(agent, "_current_phase", ""),
            checkpoint_summary=(agent.memory.checkpoint_summary if agent.memory else ""),
            tool_strategy=getattr(agent, "_last_tool_strategy", ""),
        )
        try:
            msg = agent._call()
        except Exception as e:
            agent.emit("error", {"message": f"API error: {e}"})
            return {
                **state,
                "messages": list(agent.messages),
                "pending_tool_calls": [],
                "rounds": agent.step,
                "stop_reason": "api_error",
            }

        if msg.content:
            agent.emit("thought", {"text": msg.content, "type": "reasoning"})

        tool_calls = list(msg.tool_calls or [])[:agent.max_tool_calls_per_turn]
        raw_tool_calls = list(msg.tool_calls_raw or [])[:len(tool_calls)]
        assistant_message = {
            "role": "assistant",
            "content": msg.content or "",
            "tool_calls": raw_tool_calls,
        }
        messages = list(agent.messages) + [assistant_message]
        pending = [
            {
                "id": tc.id,
                "name": tc.function.name,
                "arguments": tc.function.arguments,
            }
            for tc in tool_calls
        ]
        return {
            **state,
            "messages": messages,
            "pending_tool_calls": pending,
            "rounds": agent.step,
            "stop_reason": "" if pending else "no_tool_calls",
        }

    def run_tools(state: SolverState) -> SolverState:
        agent.messages = list(state.get("messages") or [])
        tool_messages = []
        had_progress = False
        submitted = False

        for tc in state.get("pending_tool_calls") or []:
            if not agent.running:
                break
            fn = tc.get("name") or ""
            agent._trace_loop("tool_start", tool=fn)
            args, err = agent._parse_tool_args(tc.get("arguments"))
            if err:
                result = f"[tool error] {fn}: {err}"
                agent.emit("error", {"message": result})
            else:
                try:
                    result = agent._dispatch(fn, args)
                except Exception as e:
                    result = f"[tool error] {fn}: {e}"
                    agent.emit("error", {"message": str(e)})

            tool_messages.append({
                "role": "tool",
                "tool_call_id": tc.get("id"),
                "content": agent._compact_tool_result_for_context(result),
            })
            if agent._last_tool_progress:
                had_progress = True
            agent._record_tool_result(fn, result, bool(agent._last_tool_progress))
            agent._trace_loop("tool_end", tool=fn, progress=bool(agent._last_tool_progress))

            # Spec B: a flag candidate no longer ends the run by itself. We stop the tool loop
            # only when the agent actually halted (a verified flag under the stop policy set
            # agent.running = False). Scraped/decoy candidates keep the loop alive.
            if not agent.running:
                submitted = True
                break

        agent.messages = list(agent.messages) + tool_messages
        if agent.memory:
            agent._sync_evidence_to_memory()
            agent.memory.save()
        return {
            **state,
            "messages": list(agent.messages),
            "pending_tool_calls": [],
            "submitted": submitted,
            "last_progress": had_progress,
            "stop_reason": "submitted" if submitted else "",
            "nudges": 0,
        }

    def nudge(state: SolverState) -> SolverState:
        # The model narrated a plan but called no tool. Push it over the recon->exploit
        # cliff instead of ending the run (this is what killed trx-markdown2 at 0 tool calls).
        messages = list(state.get("messages") or [])
        messages.append({
            "role": "user",
            "content": (
                "You stopped without calling a tool, but the challenge is not solved yet. Do NOT "
                "end here. Take the next concrete action now: if you already understand the "
                "vulnerability, WRITE the exploit/solver with write_file and run it; if you have a "
                "candidate flag, verify it from an independent source; if a path is dead, switch "
                "primitives. Call a tool."
            ),
        })
        agent.emit("thought", {
            "text": "No tool call emitted — nudging toward exploitation instead of stopping.",
            "type": "system",
        })
        return {**state, "messages": messages, "nudges": int(state.get("nudges") or 0) + 1,
                "pending_tool_calls": [], "stop_reason": ""}

    def after_model(state: SolverState) -> Literal["tools", "nudge", "__end__"]:
        if state.get("pending_tool_calls"):
            return "tools"
        chal = get_challenge(agent.cid) or {}
        if (agent.running
                and int(state.get("nudges") or 0) < 2
                and chal.get("status") not in {"pending_approval", "solved"}
                and int(state.get("rounds") or 0) < max_steps):
            return "nudge"
        return END

    def after_tools(state: SolverState) -> Literal["model", "__end__"]:
        if state.get("submitted"):
            return END
        if not agent.running:
            return END
        if int(state.get("rounds") or 0) >= max_steps:
            return END
        return "model"

    builder = StateGraph(SolverState)
    builder.add_node("model", call_model)
    builder.add_node("tools", run_tools)
    builder.add_node("nudge", nudge)
    builder.add_edge(START, "model")
    builder.add_conditional_edges("model", after_model)
    builder.add_conditional_edges("tools", after_tools)
    builder.add_edge("nudge", "model")
    graph = builder.compile()
    return graph.invoke(
        {
            "messages": list(initial_messages),
            "pending_tool_calls": [],
            "rounds": max(0, int(start_round or 0)),
            "submitted": False,
            "last_progress": False,
            "stop_reason": "",
            "nudges": 0,
        },
        config={"recursion_limit": max(20, max_steps * 3 + 5)},
    )
