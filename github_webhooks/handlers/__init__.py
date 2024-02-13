from .ping import PingPayload, handle_ping
from .registry import HandlersRegistry

__all__ = (
    'HandlersRegistry',
    'registry',
)


registry = HandlersRegistry()
registry.add_handler('ping', PingPayload, handle_ping)
