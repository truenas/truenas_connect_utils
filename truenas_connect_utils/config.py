import asyncio
from typing import Any, Callable


THREAD_FUNC: Callable = asyncio.to_thread


def get_account_id_and_system_id(config: dict) -> dict | None:
    jwt_details = config['registration_details'] or {}
    if all(jwt_details.get(k) for k in ('account_id', 'system_id')) is False:
        return None

    return {
        'account_id': jwt_details['account_id'],
        'system_id': jwt_details['system_id'],
    }


def set_thread_func(func: Callable) -> None:
    global THREAD_FUNC
    THREAD_FUNC = func


async def run_in_thread(func, *args) -> Any:
    return await THREAD_FUNC(func, *args)
