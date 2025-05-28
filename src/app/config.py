from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    HOST: str = Field(default='localhost')
    PORT: int = Field(default=8000)
    GOOGLE_OAUTH_CLIENT_ID: str = Field(default='')
    GOOGLE_OAUTH_CLIENT_SECRET: str = Field(default='')

    model_config = SettingsConfigDict(
        env_file='.env',
        env_file_encoding='utf-8',
    )


settings = Settings()
