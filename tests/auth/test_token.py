from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from fastapi import HTTPException
from jose import JWTError, jwt

from app.auth.models import TokenData
from app.auth.token import (
    create_access_token,
    create_refresh_token,
    decode_token,
    verify_token,
)
from app.config import settings


def test_create_access_token_success():
    """Test successful token creation."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_access_token(data)
    assert isinstance(token, str)
    assert len(token) > 0


def test_create_access_token_payload():
    """Test that the token payload is correct."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_access_token(data)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.SIGNATURE_ALGORITHM])
    assert payload['sub'] == data['sub']
    assert payload['email'] == data['email']
    assert 'exp' in payload

    # Check if 'exp' is approximately correct
    expected_expiry = datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    actual_expiry = datetime.fromtimestamp(payload['exp'], tz=ZoneInfo('Asia/Tokyo'))
    assert abs((actual_expiry - expected_expiry).total_seconds()) < 5  # Allow 5s difference


def test_create_access_token_default_expiry():
    """Test default token expiry."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_access_token(data)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.SIGNATURE_ALGORITHM])
    expected_expiry_timestamp = (
        datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    ).timestamp()
    assert abs(payload['exp'] - expected_expiry_timestamp) < 5  # Allow 5s difference


# Tests for settings injection
def test_create_and_decode_with_custom_key():
    """Test creating and decoding a token with a custom JWT_SECRET_KEY."""
    custom_settings = settings.model_copy(deep=True)
    custom_settings.JWT_SECRET_KEY = 'custom_test_secret_key'  # pragma: allowlist secret # noqa: S105

    data = {'sub': 'customkeyuser@example.com', 'email': 'customkeyuser@example.com'}
    token = create_access_token(data, current_settings=custom_settings)

    # Decode with the same custom settings
    token_data = decode_token(token, current_settings=custom_settings)
    assert token_data.sub == data['sub']

    # Attempting to decode with global/default settings should fail if the key is different
    # and the global JWT_SECRET_KEY is not the same as custom_test_secret_key
    if settings.JWT_SECRET_KEY != custom_settings.JWT_SECRET_KEY:
        with pytest.raises(HTTPException) as exc_info:
            decode_token(token)  # Uses global settings
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == '無効なトークンです'


def test_create_with_custom_expiry():
    """Test creating a token with custom ACCESS_TOKEN_EXPIRE_MINUTES."""
    custom_settings = settings.model_copy(deep=True)
    custom_settings.ACCESS_TOKEN_EXPIRE_MINUTES = 10

    data = {'sub': 'customexpiry@example.com'}
    token = create_access_token(data, current_settings=custom_settings)

    payload = jwt.decode(
        token,
        custom_settings.JWT_SECRET_KEY,
        algorithms=[custom_settings.SIGNATURE_ALGORITHM],
    )
    expected_expiry_timestamp = (
        datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(minutes=custom_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    ).timestamp()
    assert abs(payload['exp'] - expected_expiry_timestamp) < 5


def test_verify_with_custom_key_failure():
    """Test verify_token fails if token is created with default key and verified with a different custom key."""
    data = {'sub': 'verifycustom@example.com'}
    # Token created with global/default settings
    token = create_access_token(data)

    custom_settings = settings.model_copy(deep=True)
    custom_settings.JWT_SECRET_KEY = 'a_very_different_secret_key_for_failure_test'  # pragma: allowlist secret # noqa: S105

    # Ensure the custom key is actually different for the test to be meaningful
    assert settings.JWT_SECRET_KEY != custom_settings.JWT_SECRET_KEY

    with pytest.raises(HTTPException) as exc_info:
        verify_token(token, current_settings=custom_settings)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == '無効なトークンです'  # decode_token within verify_token will fail


def test_refresh_token_with_custom_settings():
    """Test create_refresh_token with custom REFRESH_TOKEN_EXPIRE_DAYS and custom key."""
    custom_settings = settings.model_copy(deep=True)
    custom_settings.REFRESH_TOKEN_EXPIRE_DAYS = 1  # Shorten for test
    custom_settings.JWT_SECRET_KEY = 'custom_refresh_secret_key'  # pragma: allowlist secret # noqa: S105

    data = {'sub': 'customrefresh@example.com'}
    token = create_refresh_token(data, current_settings=custom_settings)

    payload = jwt.decode(
        token,
        custom_settings.JWT_SECRET_KEY,
        algorithms=[custom_settings.SIGNATURE_ALGORITHM],
    )
    expected_expiry_timestamp = (
        datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(days=custom_settings.REFRESH_TOKEN_EXPIRE_DAYS)
    ).timestamp()
    assert abs(payload['exp'] - expected_expiry_timestamp) < 60  # Using 60s leeway as in other refresh token tests

    # Verify with custom settings (should pass as token is not expired yet and key matches)
    token_data = verify_token(token, current_settings=custom_settings)
    assert token_data.sub == data['sub']

    # Verify with default settings (should fail due to key mismatch)
    if settings.JWT_SECRET_KEY != custom_settings.JWT_SECRET_KEY:
        with pytest.raises(HTTPException) as exc_info:
            verify_token(token)  # Uses global settings
        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == '無効なトークンです'


def test_verify_token_success():
    """Test successful token verification for a valid token."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_access_token(data)
    token_data = verify_token(token)
    assert token_data.sub == data['sub']
    assert token_data.email == data['email']


def test_verify_token_expired():
    """Test that verifying an expired token raises HTTPException."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    # Create an already expired token
    expired_token = create_access_token(data, expires_delta=timedelta(seconds=-1))
    with pytest.raises(HTTPException) as exc_info:
        verify_token(expired_token)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == 'トークンの有効期限が切れています'


def test_verify_token_invalid_signature():
    """Test verifying a token with an invalid signature raises HTTPException."""
    # Create a token with the default key
    valid_payload = {
        'sub': 'testuser@example.com',
        'exp': datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(minutes=15),
    }

    # Create another token with a different key, making its signature invalid for the default key
    token_signed_incorrectly = jwt.encode(valid_payload, 'DIFFERENT_KEY', algorithm=settings.SIGNATURE_ALGORITHM)

    with pytest.raises(HTTPException) as exc_info:
        verify_token(token_signed_incorrectly)  # This token's signature won't match settings.JWT_SECRET_KEY
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == '無効なトークンです'


def test_verify_token_malformed():
    """Test verifying a malformed token raises HTTPException."""
    malformed_token = 'this.is.not.a.valid.jwt'  # pragma: allowlist secret # noqa: S105
    with pytest.raises(HTTPException) as exc_info:
        verify_token(malformed_token)
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == '無効なトークンです'


def test_decode_token_success():
    """Test successful token decoding."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_access_token(data)
    token_data = decode_token(token)
    assert token_data.sub == data['sub']
    assert token_data.email == data['email']


def test_decode_token_invalid_signature():
    """Test decoding a token with an invalid signature."""
    # Token signed with the correct key
    # Attempt to decode with a different key (by manipulating settings temporarily or creating a token with another key)
    original_key = settings.JWT_SECRET_KEY
    settings.JWT_SECRET_KEY = 'another_secret_key'  # pragma: allowlist secret # noqa: S105
    # Re-encode with a different key to make it invalid for the original key
    invalid_token_payload = {
        'sub': 'testuser@example.com',
        'email': 'testuser@example.com',
        'exp': datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(minutes=15),
    }
    invalid_token = jwt.encode(
        invalid_token_payload,
        'another_secret_key_to_make_it_fail',
        algorithm=settings.SIGNATURE_ALGORITHM,
    )
    settings.JWT_SECRET_KEY = original_key  # Restore original key for decode attempt

    with pytest.raises(HTTPException) as exc_info:
        decode_token(invalid_token)
    assert exc_info.value.status_code == 401


def test_decode_token_malformed():
    """Test decoding a malformed token."""
    malformed_token = 'this.is.not.a.valid.token'  # pragma: allowlist secret # noqa: S105
    with pytest.raises(HTTPException) as exc_info:
        decode_token(malformed_token)
    assert exc_info.value.status_code == 401


def test_decode_token_expired_but_decodable():
    """Test decoding an expired token (decode_token itself doesn't check expiry)."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    # Create an already expired token
    expired_token = create_access_token(data, expires_delta=timedelta(seconds=-3600))
    token_data = decode_token(expired_token)
    assert token_data.sub == data['sub']
    assert token_data.email == data['email']
    assert token_data.exp is not None
    # Verify it is indeed expired by checking the timestamp
    assert datetime.fromtimestamp(token_data.exp, tz=ZoneInfo('Asia/Tokyo')) < datetime.now(tz=ZoneInfo('Asia/Tokyo'))


def test_create_refresh_token_success():
    """Test successful refresh token creation."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_refresh_token(data)
    assert isinstance(token, str)
    assert len(token) > 0


def test_create_refresh_token_payload():
    """Test that the refresh token payload is correct."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_refresh_token(data)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.SIGNATURE_ALGORITHM])
    assert payload['sub'] == data['sub']
    assert payload['email'] == data['email']
    assert 'exp' in payload

    # Check if 'exp' is approximately correct
    expected_expiry = datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    actual_expiry = datetime.fromtimestamp(payload['exp'], tz=ZoneInfo('Asia/Tokyo'))
    # Allow a larger difference for refresh tokens due to longer expiry
    assert abs((actual_expiry - expected_expiry).total_seconds()) < 60


def test_create_refresh_token_expiry():
    """Test refresh token expiry."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    token = create_refresh_token(data)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.SIGNATURE_ALGORITHM])
    expected_expiry_timestamp = (
        datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    ).timestamp()
    # Allow a larger difference for refresh tokens due to longer expiry
    assert abs(payload['exp'] - expected_expiry_timestamp) < 60


def test_create_access_token_custom_expiry():
    """Test custom token expiry."""
    data = {'sub': 'testuser@example.com', 'email': 'testuser@example.com'}
    custom_delta = timedelta(hours=1)
    token = create_access_token(data, expires_delta=custom_delta)
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.SIGNATURE_ALGORITHM])
    expected_expiry_timestamp = (datetime.now(tz=ZoneInfo('Asia/Tokyo')) + custom_delta).timestamp()
    assert abs(payload['exp'] - expected_expiry_timestamp) < 5  # Allow 5s difference
