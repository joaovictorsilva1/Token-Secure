from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    DB_HOST: str = "db"
    DB_PORT: int = 3306
    DB_USER: str = "app"
    DB_PASSWORD: str = "app123"
    DB_NAME: str = "tokensecure"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_SECRET: str = "change"
    JWT_REFRESH_SECRET: str = "change"
    CORS_ORIGINS: str = "http://localhost:3000"
settings = Settings()