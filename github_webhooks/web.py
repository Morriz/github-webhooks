import hmac
import json
import logging
import urllib.parse
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import TypeAdapter

from .schemas import WebhookHeaders

router = APIRouter()


@router.post('/hook')
async def webhook_handler(
    request: Request,
    background_tasks: BackgroundTasks,
) -> str:
    headers = TypeAdapter(WebhookHeaders).validate_python(request.headers, strict=False)
    payload_body: bytes = await request.body()

    verify_signature(payload_body, headers, request.app.secret_token)

    # some issues arose when github decided to send the payload as two parts sometimes:
    # - payload=...
    # - &project=...
    # so we have to accomodate for that

    # Convert bytes to string first
    payload = payload_body.decode('utf-8')

    # Try parsing as direct JSON first
    try:
        # First attempt: direct JSON parsing
        json.loads(payload)
    except json.JSONDecodeError:
        # If direct parsing fails, try URL decoding
        try:
            # Remove 'payload=' prefix if exists
            if payload.startswith('payload='):
                payload = payload[8:]
                # also remove last part with and after last occurence of '&'
                payload = payload[: payload.rindex('&')]

            # URL decode
            payload = urllib.parse.unquote(payload)

            # Parse decoded payload
            json.loads(payload)
        except (json.JSONDecodeError, TypeError) as e:
            # If all parsing attempts fail, raise an informative error
            raise ValueError(f"Unable to parse payload: {e}") from e

    result = await request.app.hooks.handle(
        headers.event,
        payload,
        headers=headers,
        query_params=request.query_params,
        background_tasks=background_tasks,
    )

    return result or 'OK'


def verify_signature(payload_body: bytes, headers: WebhookHeaders, secret_token: Optional[str]) -> None:

    if not secret_token:
        # validation is disabled
        return

    if not headers.signature_256:
        logging.error('Request is missing signature header')
        raise HTTPException(status_code=403, detail='signature verification failed')

    signature = hmac.new(secret_token.encode('utf-8'), payload_body, 'sha256').hexdigest()

    if not hmac.compare_digest(f'sha256={signature}', headers.signature_256):
        logging.error(
            'Signature verification failed "%s" != "%s"',
            f'sha256={signature}',
            headers.signature_256,
        )
        raise HTTPException(status_code=403, detail='signature verification failed')
