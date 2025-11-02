from pydantic_settings import BaseSettings
class Settings(BaseSettings):
    DB_HOST: str 
    DB_PORT: int = 3306
    DB_USER: str 
    DB_PASSWORD: str 
    DB_NAME: str 
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    JWT_SECRET: str 
    JWT_REFRESH_SECRET: str 
    CORS_ORIGINS: str 
settings = Settings()