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
    KAFKA_BROKER: str = os.getenv("KAFKA_BROKER", "kafka:9092")
    VULN_REFRESH_TOPIC: str = os.getenv("VULN_REFRESH_TOPIC", "vuln.refresh")
    RESCAN_SCHEDULER_INTERVAL_MINUTES: int = int(
        os.getenv("RESCAN_SCHEDULER_INTERVAL_MINUTES", "5")
    )
    DEFAULT_RESCAN_FREQUENCY_HOURS: int = int(
        os.getenv("DEFAULT_RESCAN_FREQUENCY_HOURS", "24")
    )

    class Config:
        env_file = ".env"


settings = Settings()
