

from sqlmodel import SQLModel,Session,create_engine
from fastapi_todoapp1 import setting


connection_string: str = str(setting.DATABASE_URL).replace(
    "postgresql", "postgresql+psycopg")
engine = create_engine(connection_string, connect_args={
                       "sslmode": "require"}, pool_recycle=300, pool_size=10, echo=True)


def create_tables():
    SQLModel.metadata.create_all(
        engine
    )


def get_Session():
    with Session(engine) as session:
        yield session
