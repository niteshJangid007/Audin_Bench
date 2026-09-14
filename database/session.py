"""
Database session management for Audit Bench.
Handles connection creation, pooling, and dependency injection.
"""
import os
from collections.abc import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from database.models import Base

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./audit_bench.db")

connect_args = {}
if DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
    echo=False,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def init_db() -> None:
    """Create all database tables if they do not already exist."""
    Base.metadata.create_all(bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for request-scoped database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
