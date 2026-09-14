"""
Audit Bench API Configuration.
Loads settings from environment variables using standard Pydantic and dotenv.
Zero external dependency requirement.
"""
import os
from functools import lru_cache
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseModel):
    environment: str = os.getenv("ENVIRONMENT", "development")
    api_v1_prefix: str = os.getenv("API_V1_PREFIX", "/api/v1")
    port: int = int(os.getenv("PORT", "8000"))

    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./audit_bench.db")
    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    github_app_id: str = os.getenv("GITHUB_APP_ID", "100001")
    github_app_private_key: str = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    github_webhook_secret: str = os.getenv("GITHUB_WEBHOOK_SECRET", "development_webhook_secret_key_8820")
    github_client_id: str = os.getenv("GITHUB_CLIENT_ID", "")
    github_client_secret: str = os.getenv("GITHUB_CLIENT_SECRET", "")

    jwt_secret: str = os.getenv("JWT_SECRET", "super_secret_jwt_key_audit_bench_dev_32_bytes_len")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    access_token_expire_minutes: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))


@lru_cache
def get_settings() -> Settings:
    return Settings()
