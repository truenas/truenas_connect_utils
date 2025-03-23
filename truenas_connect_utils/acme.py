import logging
from urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from josepy import JWKRSA
from jsonschema import validate as jsonschema_validate, ValidationError as JSONValidationError
from truenas_acme_utils.issue_cert import issue_certificate

from .cert import CERT_BOT_EMAIL, get_hostnames_from_hostname_config, generate_csr
from .config import get_account_id_and_system_id, run_in_thread
from .exceptions import CallError
from .hostname import hostname_config
from .request import call
from .tnc_authenticator import TrueNASConnectAuthenticator
from .urls import get_acme_config_url


logger = logging.getLogger('truenas_connect')


ACME_CONFIG_JSON_SCHEMA = {
    '$schema': 'http://json-schema.org/draft-07/schema#',
    'type': 'object',
    'properties': {
        'endpoint': {
            'type': 'string',
        },
        'account': {
            'type': 'object',
            'properties': {
                'status': {
                    'type': 'string',
                },
                'uri': {
                    'type': 'string',
                },
                'key': {
                    'type': 'string',
                }
            },
            'required': ['status', 'uri', 'key'],
            'additionalProperties': True,
        }
    },
    'required': ['endpoint', 'account'],
    'additionalProperties': True,
}


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
    try:
        jsonschema_validate(config['acme_details'], ACME_CONFIG_JSON_SCHEMA)
    except JSONValidationError as e:
        config['error'] = f'Failed to validate ACME config: {e}'
        return config

    acme_details = config['acme_details']
    private_key = serialization.load_pem_private_key(
        acme_details['account']['key'].encode(), password=None, backend=default_backend()
    )
    jwk_rsa = JWKRSA(key=private_key)
    parsed_url = urlparse(f'https://{acme_details["endpoint"]}')
    config['acme_details'] = {
        'uri': acme_details['account']['uri'],
        'directory': acme_details['endpoint'],
        'tos': True,
        'new_account_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/new-acct',
        'new_nonce_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/new-nonce',
        'new_order_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/new-order',
        'revoke_cert_uri': f'{parsed_url.scheme}://{parsed_url.netloc}/acme/revoke-cert',
        'body': {
            'contact': CERT_BOT_EMAIL,
            'status': acme_details['account']['status'],
            'key': jwk_rsa.json_dumps(),
        }
    }
    return config


async def create_cert(tnc_config: dict) -> dict:
    tnc_hostname_config = await hostname_config(tnc_config)
    if tnc_hostname_config['error']:
        raise CallError(f'Failed to fetch TN Connect hostname config: {tnc_hostname_config["error"]}')

    tnc_acme_config = await acme_config(tnc_config)
    if tnc_acme_config['error']:
        raise CallError(f'Failed to fetch TN Connect ACME config: {tnc_acme_config["error"]}')

    hostnames = get_hostnames_from_hostname_config(tnc_hostname_config)
    csr, private_key = await run_in_thread(generate_csr, hostnames)
    authenticator_mapping = {f'DNS:{hostname}': TrueNASConnectAuthenticator(tnc_config) for hostname in hostnames}
    final_order = await run_in_thread(issue_certificate, tnc_acme_config['acme_details'], csr, authenticator_mapping)
    return {
        'cert': final_order.fullchain_pem,
        'acme_uri': final_order.uri,
        'private_key': private_key,
        'csr': csr,
    }
