from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from app.auth.models import TokenData
from app.auth.token import verify_token

# トークン取得用のエンドポイントを指定
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='api/auth/token')


async def get_current_user(token: str = Depends(oauth2_scheme)) -> TokenData:
    """
    現在のユーザーを取得する依存関数

    Args:
        token: リクエストから取得したJWTトークン

    Returns:
        検証済みのユーザーデータ

    Raises:
        HTTPException: 認証に失敗した場合
    """
    try:
        return verify_token(token)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='認証に失敗しました',
            headers={'WWW-Authenticate': 'Bearer'},
        ) from e
