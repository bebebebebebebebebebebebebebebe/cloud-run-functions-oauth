import secrets
from typing import Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from app.auth.dependencies import get_current_user
from app.auth.models import TokenData, TokenResponse, UserInfo
from app.auth.oauth import (
    exchange_code_for_token,
    get_google_auth_url,
    get_google_user_info,
)
from app.auth.token import create_access_token, create_refresh_token, verify_token
from app.config import settings
from app.logger import get_logger

logger = get_logger(__name__)

router = APIRouter(
    prefix='/api/auth',
    tags=['認証'],
    responses={401: {'description': '認証に失敗しました'}},
)


@router.get('/login/google')
async def login_google(request: Request):
    """
    Google認証のためのリダイレクトURLを生成する

    Returns:
        RedirectResponse: Google認証ページへのリダイレクト
    """
    # CSRFトークンの生成
    state = secrets.token_urlsafe(32)

    # 認証用URLの生成
    auth_url = get_google_auth_url(settings.GOOGLE_OAUTH_REDIRECT_URI, state)
    return RedirectResponse(auth_url)


@router.get('/callback/google')
async def google_callback(code: str, state: Optional[str] = None):
    """
    Google認証コールバック処理

    Args:
        code: Googleからのレスポンスに含まれる認証コード
        state: CSRF対策用のステート値

    Returns:
        TokenResponse: アクセストークンとリフレッシュトークン
    """
    try:
        # 認証コードをトークンと交換
        token_data = await exchange_code_for_token(code, settings.GOOGLE_OAUTH_REDIRECT_URI)

        # ユーザー情報の取得
        user_info = await get_google_user_info(token_data['access_token'])

        # JWT発行に必要なデータ
        token_payload = {'sub': user_info.id, 'email': user_info.email}

        # JWTトークンの生成
        access_token = create_access_token(token_payload)
        refresh_token = create_refresh_token(token_payload)

        return TokenResponse(access_token=access_token, refresh_token=refresh_token)

    except Exception as e:
        logger.error(f'認証エラー: {str(e)}')
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f'認証処理中にエラーが発生しました: {str(e)}',
        ) from e


@router.post('/refresh')
async def refresh_token(refresh_token: str) -> TokenResponse:
    """
    リフレッシュトークンを使用して新しいアクセストークンを取得

    Args:
        refresh_token: 有効なリフレッシュトークン

    Returns:
        TokenResponse: 新しいアクセストークンとリフレッシュトークン

    Raises:
        HTTPException: リフレッシュトークンが無効な場合
    """
    try:
        # リフレッシュトークンの検証
        token_data = verify_token(refresh_token)

        # 新しいトークンペイロード
        token_payload = {'sub': token_data.sub, 'email': token_data.email}

        # 新しいトークンの生成
        new_access_token = create_access_token(token_payload)
        new_refresh_token = create_refresh_token(token_payload)

        return TokenResponse(access_token=new_access_token, refresh_token=new_refresh_token)

    except HTTPException as e:
        # すでに適切なHTTPExceptionが発生している場合はそのまま再スロー
        raise e
    except Exception as e:
        logger.error(f'トークン更新エラー: {str(e)}')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='リフレッシュトークンが無効です',
        ) from e


@router.get('/me', response_model=UserInfo)
async def get_user_me(current_user: TokenData = Depends(get_current_user)):
    """
    現在ログイン中のユーザー情報を取得

    Args:
        current_user: 現在認証されているユーザー

    Returns:
        UserInfo: ユーザー情報
    """
    # 実際のアプリケーションでは、データベースからユーザー情報を取得する
    # この例では簡略化のため、トークンから取得した情報のみを返す
    return UserInfo(
        id=current_user.sub,
        email=current_user.email,
        name=current_user.email.split('@')[0],  # 仮の名前としてメールアドレスのユーザー部分を使用
    )


@router.post('/logout')
async def logout():
    """
    ログアウト処理

    クライアント側でトークンを削除する指示を返す
    Returns:
        Dict[str, str]: ログアウトメッセージ
    """
    return {'message': 'ログアウトしました'}
