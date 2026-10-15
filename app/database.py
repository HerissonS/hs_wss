import os
from pathlib import Path
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.config import settings

# Ensure data directory exists
db_file = Path(settings.DB_PATH)
db_file.parent.mkdir(parents=True, exist_ok=True)

# SQLite database URL
DATABASE_URL = f"sqlite:///{settings.DB_PATH}"

# Create engine with thread-safe settings for FastAPI and background tasks
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=settings.DEBUG
)

# Session factory with expire_on_commit=False to allow serialization outside context
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, expire_on_commit=False)

# Declarative Base for models
Base = declarative_base()


from sqlalchemy import text


def purge_data() -> None:
    """
    Purges previous execution records (findings, visited_urls, scans)
    to provide a clean slate for the new session.
    """
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM findings"))
        conn.execute(text("DELETE FROM visited_urls"))
        conn.execute(text("DELETE FROM scans"))
        try:
            conn.execute(text("VACUUM"))
        except Exception:
            pass


def init_db(purge: bool = False) -> None:
    """
    Initializes database tables.
    If purge is True, purges previous execution data so the session starts fresh.
    """
    Base.metadata.create_all(bind=engine)
    
    # Safe migration: add raw_value column if table exists from previous run without it
    with engine.begin() as conn:
        try:
            res = conn.execute(text("PRAGMA table_info(findings)")).fetchall()
            col_names = [col[1] for col in res]
            if "raw_value" not in col_names:
                conn.execute(text("ALTER TABLE findings ADD COLUMN raw_value TEXT"))
        except Exception:
            # Ignore safely if table was just created by create_all
            pass

        try:
            res_scans = conn.execute(text("PRAGMA table_info(scans)")).fetchall()
            scan_cols = [col[1] for col in res_scans]
            if "auth_status" not in scan_cols:
                conn.execute(text("ALTER TABLE scans ADD COLUMN auth_status TEXT"))
            if "auth_message" not in scan_cols:
                conn.execute(text("ALTER TABLE scans ADD COLUMN auth_message TEXT"))
        except Exception:
            pass

    if purge:
        purge_data()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI dependency that yields a database session.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def get_db_context() -> Generator[Session, None, None]:
    """
    Context manager for background tasks and non-request threads.
    """
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
