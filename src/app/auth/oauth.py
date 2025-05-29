import json
from typing import Dict, Optional

import httpx
from fastapi import HTTPException, status
from google.auth.transport import requests
from google.oauth2 import id_token

from app.auth.models import UserInfo
from app.config import settings
from app.logger import get_logger

logger = get_logger(__name__)


def get_google_auth_url(redirect_uri: str, state: Optional[str] = None) -> str:
    """
    Googleログイン用のURLを生成する

    Args:
        redirect_uri: 認証後のリダイレクト先URL
        state: CSRF対策用のランダム文字列

    Returns:
        認証用URL
    """
    params = {
        'client_id': settings.GOOGLE_OAUTH_CLIENT_ID,
        'response_type': 'code',
        'scope': 'openid email profile',
        'redirect_uri': redirect_uri,
        'access_type': 'offline',
        'prompt': 'consent',  # 毎回同意画面を表示し、リフレッシュトークンを確実に取得
    }

    if state:
        params['state'] = state

    # URLパラメータの生成
    query_string = '&'.join([f'{key}={value}' for key, value in params.items()])
    return f'{settings.GOOGLE_AUTH_URL}?{query_string}'


async def exchange_code_for_token(code: str, redirect_uri: str) -> Dict[str, str]:
    """
    認証コードをトークンと交換する

    Args:
        code: Googleから取得した認証コード
        redirect_uri: リダイレクト先URL（認証時と同じものを指定）

    Returns:
        アクセストークン、リフレッシュトークンなどを含む辞書

    Raises:
        HTTPException: トークン交換に失敗した場合
    """
    async with httpx.AsyncClient() as client:
        try:
            token_data = {
                'client_id': settings.GOOGLE_OAUTH_CLIENT_ID,
                'client_secret': settings.GOOGLE_OAUTH_CLIENT_SECRET,
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': redirect_uri,
            }

            response = await client.post(settings.GOOGLE_TOKEN_URL, data=token_data)
            response.raise_for_status()
            return response.json()

        except httpx.HTTPStatusError as e:
            logger.error(f'トークン交換エラー: {e.response.text}')
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='認証コードの交換に失敗しました',
            ) from e
        except Exception as e:
            logger.error(f'予期しないエラー: {str(e)}')
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='認証処理中にエラーが発生しました',
            ) from e


async def get_google_user_info(token: str) -> UserInfo:
    """
    Googleのアクセストークンを使ってユーザー情報を取得する

    Args:
        token: Googleのアクセストークン

    Returns:
        ユーザー情報

    Raises:
        HTTPException: ユーザー情報の取得に失敗した場合
    """
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(settings.GOOGLE_USERINFO_URL, headers={'Authorization': f'Bearer {token}'})
            response.raise_for_status()

            user_data = response.json()
            return UserInfo(
                id=user_data['sub'],
                email=user_data['email'],
                name=user_data.get('name', ''),
                picture=user_data.get('picture'),
            )

        except httpx.HTTPStatusError as e:
            logger.error(f'ユーザー情報取得エラー: {e.response.text}')
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='ユーザー情報の取得に失敗しました',
            ) from e
        except Exception as e:
            logger.error(f'予期しないエラー: {str(e)}')
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail='ユーザー情報の取得中にエラーが発生しました',
            ) from e


def verify_google_id_token(id_token_str: str) -> Dict:
    """
    Google ID Tokenを検証する

    Args:
        id_token_str: 検証するID Token

    Returns:
        検証されたトークンのペイロード

    Raises:
        HTTPException: トークンの検証に失敗した場合
    """
    try:
        # ID Tokenの検証
        idinfo = id_token.verify_oauth2_token(id_token_str, requests.Request(), settings.GOOGLE_OAUTH_CLIENT_ID)

        # 発行者の確認
        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('不正な発行者です')

        return idinfo

    except ValueError as e:
        logger.error(f'ID Token検証エラー: {str(e)}')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f'無効なIDトークンです: {str(e)}',
        ) from e
