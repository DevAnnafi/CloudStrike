from pydantic_settings import BaseSettings
from functools import lru_cache

class Settings(BaseSettings):
    APP_NAME: str = "CloudSecure API"
    VERSION: str = "2.0.0"
    DATABASE_URL: str = "sqlite:///./cloudsecure.db"
    DEBUG: bool = True
    AUTH_KEY: str = 'dev-auth-key-change-in-production' 
    API_KEY: str = 'dev-api-key-change-in-production'
    SECRET_KEY: str = "dev-secret-key-change-in-production"


    class Config:
        env_file = ".env"

@lru_cache
def get_settings():
    return Settings()

settings = get_settings()
