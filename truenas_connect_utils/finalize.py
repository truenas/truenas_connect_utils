import enum
from types import MappingProxyType
from typing import Any


class FinalizeResult(enum.Enum):
    SUCCESS = 'success'
    RETRY = 'retry'
    TERMINAL = 'terminal'


RETRYABLE_STATUS_CODES = frozenset({408, 429})
# Contract between the `error` codes TNC answers /v1/systems/finalize with and what we do about them: how the
# response is classified, and the text shown to the user. Add new TNC error codes here.
TNC_FINALIZE_ERRORS = MappingProxyType({
    'not found': (
        FinalizeResult.RETRY,
        'Waiting for registration to complete in TrueNAS Connect',
    ),
    'already finalized': (
        FinalizeResult.TERMINAL,
        'System is already registered in TrueNAS Connect. Remove it there and register again.',
    ),
    'invalid claim token': (
        FinalizeResult.TERMINAL,
        'TrueNAS Connect rejected the claim token',
    ),
    'limit exceeded': (
        FinalizeResult.TERMINAL,
        'The TrueNAS Connect account has reached its system limit',
    ),
})
RETRYABLE_400_ERROR_STRINGS = frozenset(
    error for error, (result, _) in TNC_FINALIZE_ERRORS.items() if result is FinalizeResult.RETRY
)
MAX_UNMAPPED_ERROR_LENGTH = 200


def classify_finalize_response(resp: dict[str, Any]) -> tuple[FinalizeResult, str]:
    """Classify a /v1/systems/finalize response dict from request.call().

    Decision matrix:
      - 2xx with 'token' in body              -> SUCCESS
      - 2xx without 'token'                   -> TERMINAL
      - status_code is None                   -> RETRY (network failure)
      - 5xx                                   -> RETRY
      - 408, 429                              -> RETRY
      - 400 with body['error'] == 'not found' -> RETRY (user has not yet
                                                 completed UI registration)
      - any other non-2xx                     -> TERMINAL

    Returns (result, description). `description` is a short human-readable
    string suitable for logging or storing in an initialization_error field.
    """
    status = resp.get('status_code')
    body = resp.get('response') or {}

    if status is None:
        return FinalizeResult.RETRY, resp.get('error') or 'connection error'

    if 200 <= status < 300:
        if isinstance(body, dict) and 'token' in body:
            return FinalizeResult.SUCCESS, ''
        return FinalizeResult.TERMINAL, f'token missing from successful response: {body!r}'

    if 500 <= status < 600:
        return FinalizeResult.RETRY, f'TNC {status}: {body!r}'

    if status in RETRYABLE_STATUS_CODES:
        return FinalizeResult.RETRY, f'TNC {status}: {body!r}'

    if (
        status == 400 and isinstance(body, dict) and isinstance(body.get('error'), str)
        and body['error'] in RETRYABLE_400_ERROR_STRINGS
    ):
        return FinalizeResult.RETRY, f'TNC pending registration: {body!r}'

    return FinalizeResult.TERMINAL, f'TNC {status}: {body!r}'


def get_finalize_failure_reason(resp: dict[str, Any]) -> str | None:
    """Text to show the user for a /v1/systems/finalize response classified as TERMINAL.

    Returns the display string from `TNC_FINALIZE_ERRORS`, or quotes an `error` code that is not mapped yet.
    Returns None when TNC gave no usable reason, so that the caller keeps its generic failure text. Bodies are
    never quoted, unlike the description from `classify_finalize_response`, which is meant for logs.
    """
    body = resp.get('response')
    error = body.get('error') if isinstance(body, dict) else None
    if not isinstance(error, str):
        return None

    error = error.strip()
    if error in TNC_FINALIZE_ERRORS:
        return TNC_FINALIZE_ERRORS[error][1]
    if not error or len(error) > MAX_UNMAPPED_ERROR_LENGTH or not error.isprintable():
        return None
    return f'TrueNAS Connect rejected the registration: {error}'
