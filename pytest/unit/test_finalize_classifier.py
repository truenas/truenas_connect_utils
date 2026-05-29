import pytest

from truenas_connect_utils.finalize import FinalizeResult, classify_finalize_response


def make_resp(*, status_code=None, response=None, error=None, headers=None):
    return {
        'status_code': status_code,
        'response': response if response is not None else {},
        'error': error,
        'headers': headers or {},
    }


@pytest.mark.parametrize('status_code', [200, 201, 204])
def test_2xx_with_token_is_success(status_code):
    result, _ = classify_finalize_response(make_resp(status_code=status_code, response={'token': 'abc'}))
    assert result is FinalizeResult.SUCCESS


def test_2xx_without_token_is_terminal():
    result, description = classify_finalize_response(make_resp(status_code=200, response={}))
    assert result is FinalizeResult.TERMINAL
    assert 'token missing' in description


def test_2xx_with_non_dict_body_is_terminal():
    result, _ = classify_finalize_response(make_resp(status_code=200, response='plain text'))
    assert result is FinalizeResult.TERMINAL


def test_400_with_not_found_retries():
    body = {'error': 'not found', 'data': {'entity': 'system', 'id': 'abc-123'}}
    result, description = classify_finalize_response(make_resp(status_code=400, response=body))
    assert result is FinalizeResult.RETRY
    assert 'pending registration' in description


def test_400_with_different_error_string_is_terminal():
    result, _ = classify_finalize_response(
        make_resp(status_code=400, response={'error': 'invalid claim token'})
    )
    assert result is FinalizeResult.TERMINAL


def test_400_case_sensitive_match():
    result, _ = classify_finalize_response(
        make_resp(status_code=400, response={'error': 'NOT FOUND'})
    )
    assert result is FinalizeResult.TERMINAL


def test_400_with_non_dict_body_is_terminal():
    result, _ = classify_finalize_response(make_resp(status_code=400, response='Bad Request'))
    assert result is FinalizeResult.TERMINAL


@pytest.mark.parametrize('error_value', [['not found'], {'msg': 'not found'}, None, 42])
def test_400_with_non_string_error_field_is_terminal(error_value):
    # Hardening: guard against malformed bodies where `error` is not a string.
    # Without an isinstance check, `body.get('error') in frozenset({...})` raises
    # TypeError when the value is unhashable (list/dict).
    result, _ = classify_finalize_response(
        make_resp(status_code=400, response={'error': error_value})
    )
    assert result is FinalizeResult.TERMINAL


@pytest.mark.parametrize('status_code', [401, 403, 404, 405, 422])
def test_other_4xx_is_terminal(status_code):
    result, _ = classify_finalize_response(
        make_resp(status_code=status_code, response={'error': 'whatever'})
    )
    assert result is FinalizeResult.TERMINAL


@pytest.mark.parametrize('status_code', [408, 429])
def test_transient_status_retries(status_code):
    result, _ = classify_finalize_response(make_resp(status_code=status_code, response={}))
    assert result is FinalizeResult.RETRY


@pytest.mark.parametrize('status_code', [500, 502, 503, 504])
def test_5xx_retries(status_code):
    result, _ = classify_finalize_response(
        make_resp(status_code=status_code, response={'error': 'down'})
    )
    assert result is FinalizeResult.RETRY


def test_status_code_none_with_error_retries():
    result, description = classify_finalize_response(
        make_resp(status_code=None, error='Unable to connect with TNC in 55 seconds.')
    )
    assert result is FinalizeResult.RETRY
    assert 'Unable to connect' in description


def test_status_code_none_no_error_field_still_retries():
    result, description = classify_finalize_response(make_resp(status_code=None))
    assert result is FinalizeResult.RETRY
    assert description == 'connection error'


def test_2xx_with_empty_dict_response_is_terminal():
    # After json_response=True parse failure, request.call() returns response={}
    # with error set. Classifier should treat 2xx + missing token as TERMINAL.
    result, description = classify_finalize_response(
        make_resp(status_code=200, response={}, error="HTTP 200: expected JSON, got Content-Type 'text/html'")
    )
    assert result is FinalizeResult.TERMINAL
    assert 'token missing' in description
