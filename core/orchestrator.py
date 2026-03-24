from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from core.agent import AIAgent
from core.memory import Memory
from tools.registry import ToolRegistry


@dataclass(slots=True)
class SolveResult:
    success: bool
    final_answer: str
    iterations: int
    memory: dict[str, Any]


class Orchestrator:
    """Runs the iterative solver loop until the agent finishes or max steps is hit."""

    def __init__(
        self,
        agent: AIAgent,
        tool_registry: ToolRegistry,
        max_iterations: int = 10,
    ) -> None:
        self.agent = agent
        self.tool_registry = tool_registry
        self.max_iterations = max_iterations

    def solve(self, challenge: dict[str, Any]) -> SolveResult:
        memory = Memory(challenge=challenge)

        for iteration in range(1, self.max_iterations + 1):
            decision = self.agent.decide(memory)

            if decision.done:
                return SolveResult(
                    success=True,
                    final_answer=decision.final_answer or "",
                    iterations=iteration - 1,
                    memory=memory.to_context(),
                )

            tool = self.tool_registry.get(decision.action)
            observation = tool(decision.action_input)

            memory.add_step(
                thought=decision.thought,
                action=decision.action,
                action_input=decision.action_input,
                observation=observation,
            )

        return SolveResult(
            success=False,
            final_answer="Maximum iterations reached before a final answer was produced.",
            iterations=self.max_iterations,
            memory=memory.to_context(),
        )

