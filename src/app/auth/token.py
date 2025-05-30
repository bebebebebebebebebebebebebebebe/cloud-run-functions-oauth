from datetime import datetime, timedelta
from typing import Optional
from zoneinfo import ZoneInfo

from fastapi import HTTPException, status
from jose import JWTError, jwt

from app.auth.models import TokenData
from app.config import Settings, settings


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None, current_settings: Optional[Settings] = None) -> str:
    """
    アクセストークンを生成する

    Args:
        data: トークンに含めるデータ
        expires_delta: 有効期限（指定しない場合はデフォルト値を使用）

    Returns:
        生成されたJWTトークン
    """
    to_encode = data.copy()
    effective_settings = current_settings or settings

    if expires_delta:
        expire = datetime.now(tz=ZoneInfo('Asia/Tokyo')) + expires_delta
    else:
        expire = datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(minutes=effective_settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({'exp': expire})
    return jwt.encode(
        to_encode,
        effective_settings.JWT_SECRET_KEY,
        algorithm=effective_settings.SIGNATURE_ALGORITHM,
    )


def create_refresh_token(data: dict, current_settings: Optional[Settings] = None) -> str:
    """
    リフレッシュトークンを生成する

    Args:
        data: トークンに含めるデータ

    Returns:
        生成されたJWTトークン
    """
    to_encode = data.copy()
    effective_settings = current_settings or settings
    expire = datetime.now(tz=ZoneInfo('Asia/Tokyo')) + timedelta(days=effective_settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({'exp': expire})
    return jwt.encode(
        to_encode,
        effective_settings.JWT_SECRET_KEY,
        algorithm=effective_settings.SIGNATURE_ALGORITHM,
    )


def decode_token(token: str, current_settings: Optional[Settings] = None) -> TokenData:
    """
    トークンをデコードしてデータを取得する

    Args:
        token: デコードするJWTトークン

    Returns:
        トークンから取得したデータ

    Raises:
        HTTPException: トークンが無効な場合
    """
    try:
        effective_settings = current_settings or settings
        payload = jwt.decode(
            token,
            effective_settings.JWT_SECRET_KEY,
            algorithms=[effective_settings.SIGNATURE_ALGORITHM],
            options={'verify_exp': False},
        )
        token_data = TokenData(sub=payload.get('sub'), email=payload.get('email'), exp=payload.get('exp'))
        return token_data
    except JWTError as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='無効なトークンです',
            headers={'WWW-Authenticate': 'Bearer'},
        ) from err


def verify_token(token: str, current_settings: Optional[Settings] = None) -> TokenData:
    """
    トークンを検証する

    Args:
        token: 検証するトークン

    Returns:
        検証済みのトークンデータ
    """
    effective_settings = current_settings or settings
    # Pass current_settings to decode_token if provided
    token_data = decode_token(token, current_settings=effective_settings)

    # 有効期限チェック
    if token_data.exp and datetime.fromtimestamp(token_data.exp, tz=ZoneInfo('Asia/Tokyo')) < datetime.now(tz=ZoneInfo('Asia/Tokyo')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='トークンの有効期限が切れています',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    return token_data
