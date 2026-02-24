from .registry import _agents, _logs, _log_event
from .commands import CommandsMixin
from .hints    import HintsMixin
from .flags    import FlagsMixin
from .evidence import EvidenceMixin
from .llm      import LLMMixin
from .core     import CTFAgentCore


class CTFAgent(CommandsMixin, HintsMixin, FlagsMixin, EvidenceMixin, LLMMixin, CTFAgentCore):
    pass
