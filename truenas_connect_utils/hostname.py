import logging

from .config import get_account_id_and_system_id
from .exceptions import CallError
from .request import call
from .urls import get_hostname_url


logger = logging.getLogger('truenas_connect')


async def hostname_config(tnc_config: dict) -> dict:
    creds = get_account_id_and_system_id(tnc_config)
    if not tnc_config['enabled'] or creds is None:
        return {
            'error': 'TrueNAS Connect is not enabled or not configured properly',
            'tnc_configured': False,
            'hostname_details': {},
            'base_domain': None,
            'hostname_configured': False,
        }

    resp = (await call(
        get_hostname_url(tnc_config).format(**creds), 'get', tnc_config=tnc_config, include_auth=True,
    )) | {'base_domain': None}
    resp['hostname_details'] = resp.pop('response')
    for domain in resp['hostname_details']:
        if len(domain.rsplit('.', maxsplit=4)) == 5 and domain.startswith('*.'):
            resp['base_domain'] = domain.split('.', maxsplit=1)[-1]
            break

    return resp | {
        'tnc_configured': True,
        'hostname_configured': bool(resp['hostname_details']),
    }


async def register_update_ips(tnc_config: dict, ips: list[str], create_wildcard: bool) -> dict:
    logger.debug(
        'Updating TNC hostname configuration with %r ips and with create_wildcard %r value',
        ','.join(ips), create_wildcard
    )
    config = await hostname_config(tnc_config)
    if config['error']:
        raise CallError(f'Failed to fetch TNC hostname configuration: {config["error"]}')

    creds = get_account_id_and_system_id(tnc_config)
    return await call(
        get_hostname_url(tnc_config).format(**creds), 'put', payload={'ips': ips, 'create_wildcards': create_wildcard},
        tnc_config=tnc_config, include_auth=True,
    )
