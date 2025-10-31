from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from .config import settings

# URL de conexão com PyMySQL
DATABASE_URL = (
    f"mysql+pymysql://{settings.DB_USER}:{settings.DB_PASSWORD}"
    f"@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"
)

# Criar engine e sessão
engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependência do banco para usar no FastAPI
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

