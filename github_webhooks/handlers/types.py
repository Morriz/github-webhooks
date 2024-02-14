from typing import Any, Optional, Protocol

from fastapi import BackgroundTasks
from pydantic import BaseModel
from starlette.requests import QueryParams

from github_webhooks.schemas import WebhookHeaders

PayloadT = type[BaseModel]
HandlerResult = Optional[str]


class HandlerWithHeaders(Protocol):
    async def __call__(
        self, payload: Any, *, headers: WebhookHeaders, query_params: QueryParams, background_tasks: BackgroundTasks
    ) -> HandlerResult:
        pass  # Define the method here


class DefaultHandlerWithHeaders(Protocol):
    async def __call__(
        self,
        event: str,
        payload: bytes,
        *,
        headers: WebhookHeaders,
        query_params: QueryParams,
        background_tasks: BackgroundTasks,
    ) -> HandlerResult:
        pass  # Define the method here


Handler = HandlerWithHeaders | DefaultHandlerWithHeaders
