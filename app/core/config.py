import os
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://myesi:password@postgres:5432/myesi_db"
    # JWT
    JWT_SECRET: str = os.getenv("JWT_SECRET", "replace-with-secure-key")
    JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")

    class Config:
        env_file = ".env"


settings = Settings()
