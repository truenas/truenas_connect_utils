import logging

import jwt

from .exceptions import CallError
from .request import call
from .urls import get_token_ack_url


logger = logging.getLogger('truenas_connect')


def decode_jwt_token(token: str) -> dict:
    """
    Decode a JWT token without verification to extract claims.
    
    Args:
        token: JWT token string
        
    Returns:
        dict: Decoded JWT payload/claims
    """
    try:
        # Decode without verification - we just need to read the claims
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except jwt.DecodeError as e:
        raise CallError(f'Failed to decode JWT token: {e}')


def get_jti_from_token(token: str) -> str:
    """
    Extract JTI (JWT ID) claim from a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        str: JTI claim value
        
    Raises:
        CallError: If token cannot be decoded or JTI is missing
    """
    decoded = decode_jwt_token(token)
    jti = decoded.get('jti')
    if not jti:
        raise CallError('JWT token missing required jti claim')
    return jti
