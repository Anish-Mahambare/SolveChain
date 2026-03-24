from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class StepRecord:
    """Represents one iteration in the solver loop."""

    thought: str
    action: str
    action_input: dict[str, Any]
    observation: dict[str, Any]


@dataclass(slots=True)
class Memory:
    """Stores the running state for an iterative solve session."""

    challenge: dict[str, Any]
    steps: list[StepRecord] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add_step(
        self,
        *,
        thought: str,
        action: str,
        action_input: dict[str, Any],
        observation: dict[str, Any],
    ) -> None:
        self.steps.append(
            StepRecord(
                thought=thought,
                action=action,
                action_input=action_input,
                observation=observation,
            )
        )

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def to_context(self) -> dict[str, Any]:
        """Converts memory into a compact AI-friendly context payload."""
        return {
            "challenge": self.challenge,
            "notes": self.notes,
            "steps": [
                {
                    "thought": step.thought,
                    "action": step.action,
                    "action_input": step.action_input,
                    "observation": step.observation,
                }
                for step in self.steps
            ],
        }

