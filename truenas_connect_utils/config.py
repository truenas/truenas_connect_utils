from typing import Any


def get_account_id_and_system_id(config: dict[str, Any]) -> dict[str, Any] | None:
    jwt_details = config['registration_details'] or {}
    if not all(jwt_details.get(k) for k in ('account_id', 'system_id')):
        return None

    return {
        'account_id': jwt_details['account_id'],
        'system_id': jwt_details['system_id'],
    }
