"""Application configuration via environment variables."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    APP_ENV: str = "development"
    DATABASE_URL: str = "postgresql+psycopg2://cybersoc:changeme@localhost:5432/cybersoc"

    JWT_SECRET_KEY: str = "dev-only-change-me"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 720

    CORS_ORIGINS: str = "http://localhost:8080,http://localhost:3000"

    SEED_DEMO_USERS: bool = True

    RATE_LIMIT_LOGIN_PER_MIN: int = 20
    RATE_LIMIT_REGISTER_PER_MIN: int = 10

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
