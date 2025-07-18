import asyncio
import logging
from urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from josepy import JWKRSA
from truenas_acme_utils.issue_cert import issue_certificate

from .cert import get_hostnames_from_hostname_config, generate_csr
from .config import get_account_id_and_system_id
from .exceptions import CallError
from .hostname import hostname_config
from .request import call
from .tnc_authenticator import TrueNASConnectAuthenticator
from .urls import get_acme_config_url


logger = logging.getLogger('truenas_connect')


async def acme_config(tnc_config: dict) -> dict:
    creds = get_account_id_and_system_id(tnc_config)
    if not tnc_config['enabled'] or creds is None:
        return {
            'error': 'TrueNAS Connect is not enabled or not configured properly',
            'tnc_configured': False,
            'acme_details': {},
        }

    resp = await call(
        get_acme_config_url(tnc_config).format(account_id=creds['account_id']), 'get',
        tnc_config=tnc_config, include_auth=True,
    )
    resp['acme_details'] = resp.pop('response')
    if resp['error'] is None:
        resp = normalize_acme_config(resp)

    return resp | {
        'tnc_configured': True,
    }


def normalize_acme_config(config: dict) -> dict:
    acme_details = config.get('acme_details')
    if isinstance(acme_details, dict) is False:
        config['error'] = 'ACME config is not a dictionary'
        return config

    account_details = acme_details.get('account')
    if isinstance(account_details, dict) is False:
        config['error'] = 'ACME account details are not a dictionary'
        return config

    if missing_keys := [
        k for k in ('status', 'uri', 'key') if k not in account_details or not isinstance(account_details[k], str)
    ]:
        config['error'] = f'Missing or invalid fields in ACME account: {", ".join(missing_keys)}'
        return config

    endpoint = acme_details.get('endpoint')
    if isinstance(endpoint, str) is False:
        config['error'] = 'ACME endpoint is not a string'
        return config

    private_key = serialization.load_pem_private_key(
        account_details['key'].encode(), password=None, backend=default_backend()
    )
    jwk_rsa = JWKRSA(key=private_key)
    parsed_url = urlparse(f'https://{endpoint}')
    config['acme_details'] = {
        'uri': account_details['uri'],
        'directory': endpoint,
        'tos': True,
        'new_account_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/new-acct',
        'new_nonce_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/new-nonce',
        'new_order_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/new-order',
        'revoke_cert_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/revoke-cert',
        'body': {
            'status': account_details['status'],
            'key': jwk_rsa.json_dumps(),
        }
    }
    return config


async def create_cert(tnc_config: dict, csr_details: dict | None = None) -> dict:
    tnc_hostname_config = await hostname_config(tnc_config)
    if tnc_hostname_config['error']:
        raise CallError(f'Failed to fetch TN Connect hostname config: {tnc_hostname_config["error"]}')

    tnc_acme_config = await acme_config(tnc_config)
    if tnc_acme_config['error']:
        raise CallError(f'Failed to fetch TN Connect ACME config: {tnc_acme_config["error"]}')

    hostnames = get_hostnames_from_hostname_config(tnc_hostname_config)
    if csr_details is None:
        logger.debug('Generating CSR for TNC certificate')
        csr, private_key = await asyncio.to_thread(generate_csr, hostnames)
    else:
        logger.debug('Retrieved CSR of existing TNC certificate')
        csr, private_key = csr_details['csr'], csr_details['private_key']

    authenticator_mapping = {f'DNS:{hostname}': TrueNASConnectAuthenticator(tnc_config) for hostname in hostnames}
    logger.debug('Performing ACME challenge for TNC certificate')
    final_order = await asyncio.to_thread(
        issue_certificate, tnc_acme_config['acme_details'], csr, authenticator_mapping, 25
    )
    return {
        'cert': final_order.fullchain_pem,
        'acme_uri': final_order.uri,
        'private_key': private_key,
        'csr': csr,
    }
