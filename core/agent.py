from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.memory import Memory


@dataclass(slots=True)
class AgentDecision:
    """A normalized decision produced by the AI layer."""

    thought: str
    action: str
    action_input: dict[str, Any]
    done: bool = False
    final_answer: str | None = None


class AIAgent:
    """
    Minimal AI agent abstraction.

    Replace `decide` with a real LLM-backed planner later. For now it shows the
    expected shape of a decision in the iterative solve loop.
    """

    def decide(self, memory: Memory) -> AgentDecision:
        if not memory.steps:
            challenge_text = memory.challenge.get("description", "")
            return AgentDecision(
                thought="Start by echoing the incoming challenge details to verify loop wiring.",
                action="echo",
                action_input={"text": challenge_text},
            )

        last_observation = memory.steps[-1].observation
        return AgentDecision(
            thought="A tool result is available. End the demo loop and return the latest observation.",
            action="finish",
            action_input={},
            done=True,
            final_answer=str(last_observation),
        )

