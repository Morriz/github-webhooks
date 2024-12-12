import logging
from typing import Any, Optional

from fastapi import BackgroundTasks
from fastapi.datastructures import QueryParams

from github_webhooks.schemas import WebhookHeaders


async def handle_default(
    payload: Any,
    headers: WebhookHeaders,
    query_params: QueryParams,
    background_tasks: BackgroundTasks,
) -> Optional[str]:
    logging.debug(
        'Default handler for <%s> event, headers: %s, query_params: %s, background_tasks: %s',
        payload,
        headers,
        query_params,
        background_tasks,
    )
    return 'OK'
