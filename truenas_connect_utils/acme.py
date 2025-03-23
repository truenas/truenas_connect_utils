import logging
from urllib.parse import urlparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from josepy import JWKRSA
from jsonschema import validate as jsonschema_validate, ValidationError as JSONValidationError

from .cert import CERT_BOT_EMAIL
from .config import get_account_id_and_system_id
from .request import call
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
