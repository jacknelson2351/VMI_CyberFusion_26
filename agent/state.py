# Backward-compat shim — ChallengeMemoryStore moved to agent.memory
from agent.memory import ChallengeMemory as ChallengeMemoryStore, ChallengeMemory  # noqa: F401
