import asyncio
from typing import Any

import aiohttp
from truenas_api_client import json


def auth_headers(config: dict) -> dict:
    return {'Authorization': f'Bearer {config["jwt_token"]}'}


async def call(
    endpoint: str, mode: str, *, options: dict | None = None, payload: dict | None = None,
    headers: dict | None = None, json_response: bool = True, get_response: bool = True,
    tnc_config: dict | None = None, include_auth: bool = False,
) -> dict[str, Any]:
    options = options or {}
    timeout = options.get('timeout', 15)
    response = {
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
            async with aiohttp.ClientSession(raise_for_status=True, trust_env=True) as session:
                req = await getattr(session, mode)(
                    endpoint,
                    data=json.dumps(payload) if payload is not None else payload,
                    headers=headers,
                )
                response['status_code'] = req.status
    except asyncio.TimeoutError:
        response['error'] = f'Unable to connect with TNC in {timeout} seconds.'
    except aiohttp.ClientResponseError as e:
        response.update({
            'error': str(e),
            'status_code': e.status,
        })
    except aiohttp.ClientConnectorError as e:
        response['error'] = f'Failed to connect to TNC: {e}'
    else:
        response['headers'] = dict(req.headers)
        if get_response:
            response['response'] = await req.json() if json_response else await req.text()
    return response
