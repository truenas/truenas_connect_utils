import asyncio
from collections.abc import Callable
from typing import Any, Literal

import aiohttp
from truenas_api_client import json


Mode = Literal['get', 'post', 'put', 'delete', 'patch', 'head']


def auth_headers(config: dict[str, Any]) -> dict[str, str]:
    return {'Authorization': f'Bearer {config["jwt_token"]}'}


async def call(
    endpoint: str, mode: Mode, *, options: dict[str, Any] | None = None, payload: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None, json_response: bool = True, get_response: bool = True,
    tnc_config: dict[str, Any] | None = None, include_auth: bool = False,
) -> dict[str, Any]:
    options = options or {}
    timeout = options.get('timeout', 55)
    response: dict[str, Any] = {
        'error': None,
        'response': {},
        'status_code': None,
        'headers': {},
    }
    headers = headers or {}
    if payload is not None and (not headers or 'Content-Type' not in headers):
        headers = headers or {}
        headers['Content-Type'] = 'application/json'

    if include_auth:
        if not tnc_config:
            raise ValueError('tnc_config is required when include_auth is set')

        headers |= auth_headers(tnc_config)

    try:
        async with asyncio.timeout(timeout):
            async with aiohttp.ClientSession(trust_env=True) as session:
                session_method: Callable[..., Any] = getattr(session, mode)
                req = await session_method(
                    endpoint,
                    data=json.dumps(payload) if payload is not None else payload,
                    headers=headers,
                )
                # Capture locally first; only commit to `response` after the body
                # is fully read. If the timeout fires mid-body, status_code stays
                # None so callers see a transport failure (RETRY) rather than a
                # bogus 2xx with empty body (which would otherwise classify as
                # TERMINAL "token missing").
                status = req.status
                resp_headers = {k.title(): v for k, v in req.headers.items()}
                body: Any = {}
                if get_response:
                    if json_response:
                        try:
                            body = await req.json()
                        except (aiohttp.ContentTypeError, ValueError):
                            body = await req.text()
                    else:
                        body = await req.text()
                response['status_code'] = status
                response['headers'] = resp_headers
                response['response'] = body
                if status >= 400:
                    response['error'] = f'HTTP {status}: {body!r}'
    except asyncio.TimeoutError:
        response['error'] = f'Unable to connect with TNC in {timeout} seconds.'
    except aiohttp.ClientConnectorError as e:
        response['error'] = f'Failed to connect to TNC: {e}'
    return response
