from typing import Any, Optional, Protocol

from fastapi import BackgroundTasks
from fastapi.datastructures import QueryParams
from pydantic import BaseModel

from github_webhooks.schemas import WebhookHeaders

PayloadT = type[BaseModel]
HandlerResult = Optional[str]


class Handler(Protocol):
    async def __call__(
        self,
        payload: Any,
        headers: WebhookHeaders,
        query_params: QueryParams,
        background_tasks: BackgroundTasks,
    ) -> HandlerResult:
        pass  # Define the method here
