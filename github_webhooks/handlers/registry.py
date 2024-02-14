from typing import Any, Callable

from fastapi import BackgroundTasks
from starlette.requests import QueryParams

from github_webhooks.schemas import WebhookHeaders

from .default import handle_default
from .types import Handler, HandlerResult, PayloadT


class HandlersRegistry:
    _handlers: dict[str, tuple[PayloadT, Handler]]
    _default_handler: Handler

    def __init__(self) -> None:
        self._handlers = {}
        self._default_handler = handle_default

    def set_default_handler(self, handler: Handler) -> None:
        self._default_handler = handler

    def add_handler(self, event: str, payload_cls: PayloadT, handler: Handler) -> None:
        self._handlers[event] = (payload_cls, handler)

    def register(self, event: str, payload_cls: PayloadT) -> Callable[[Handler], Handler]:
        def deco(func: Handler) -> Handler:
            self.add_handler(event, payload_cls, func)
            return func

        return deco

    async def handle(
        self,
        event: str,
        payload: bytes,
        headers: WebhookHeaders,
        query_params: QueryParams,
        background_tasks: BackgroundTasks,
    ) -> HandlerResult:
        if event not in self._handlers:
            return await self._call_with_headers(
                self._default_handler,
                event,
                payload,
                headers=headers,
                query_params=query_params,
                background_tasks=background_tasks,
            )

        payload_cls, handler = self._handlers[event]

        payload_parsed = payload_cls.model_validate_json(payload)
        return await self._call_with_headers(
            handler, payload_parsed, headers=headers, query_params=query_params, background_tasks=background_tasks
        )

    @staticmethod
    async def _call_with_headers(
        handler: Handler,
        *args: Any,
        headers: WebhookHeaders,
        query_params: QueryParams,
        background_tasks: BackgroundTasks,
    ) -> HandlerResult:
        return await handler(*args, headers=headers, query_params=query_params, background_tasks=background_tasks)
