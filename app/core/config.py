from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://myesi:password@postgres:5432/myesi_db"
    SECRET_KEY: str = "replace-with-secure-key"

    class Config:
        env_file = ".env"


settings = Settings()
