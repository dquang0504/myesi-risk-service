import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://myesi:password@postgres:5432/myesi_db"
    # JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "replace-with-secure-key")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
    NOTIFICATION_SERVICE_URL: str = os.getenv(
        "NOTIFICATION_SERVICE_URL", "http://notification-service:8006"
    )
    NOTIFICATION_SERVICE_TOKEN: str = os.getenv("NOTIFICATION_SERVICE_TOKEN", "")

    class Config:
        env_file = ".env"


settings = Settings()
