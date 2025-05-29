from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    HOST: str = Field(default='localhost')
    PORT: int = Field(default=8000)
    GOOGLE_OAUTH_CLIENT_ID: str = Field(default='')
    GOOGLE_OAUTH_CLIENT_SECRET: str = Field(default='')
    GOOGLE_OAUTH_REDIRECT_URI: str = Field(default='http://localhost:8000/auth/callback')
    GOOGLE_AUTH_URL: str = Field(default='https://accounts.google.com/o/oauth2/auth')
    GOOGLE_TOKEN_URL: str = Field(default='https://oauth2.googleapis.com/token')
    GOOGLE_USERINFO_URL: str = Field(default='https://www.googleapis.com/oauth2/v3/userinfo')
    GOOGLE_DISCOVERY_URL: str = Field(default='https://accounts.google.com/.well-known/openid-configuration')

    JWT_SECRET_KEY: str = Field(default='')
    SIGNATURE_ALGORITHM: str = Field(default='HS256')
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(default=30)
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(default=7)

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
    )


settings = Settings()
