from .registry import _agents, _logs, _log_event, _load_log_events
from .commands import CommandsMixin
from .hints    import HintsMixin
from .flags    import FlagsMixin
from .evidence import EvidenceMixin
from .llm      import LLMMixin
from .tooling  import StructuredToolsMixin
from .interactive import InteractiveMixin
from .core     import CTFAgentCore


class CTFAgent(InteractiveMixin, StructuredToolsMixin, CommandsMixin, HintsMixin, FlagsMixin, EvidenceMixin, LLMMixin, CTFAgentCore):
    pass
