from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class TokenType(str, Enum):
    """トークンのタイプを定義する列挙型"""

    BEARER = 'bearer'


class TokenResponse(BaseModel):
    """アクセストークンとリフレッシュトークンのレスポンスモデル"""

    access_token: str
    refresh_token: str
    token_type: TokenType = Field(default=TokenType.BEARER, description='トークンのタイプ')


class TokenData(BaseModel):
    """トークンから抽出したデータのモデル"""

    sub: str
    email: Optional[str] = None
    exp: Optional[int] = None


class UserInfo(BaseModel):
    """ユーザー情報のモデル"""

    id: str
    email: str
    name: str
    picture: Optional[str] = None
