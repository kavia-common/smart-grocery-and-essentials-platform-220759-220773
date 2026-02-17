import os
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Sequence

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(
            f"Missing required environment variable '{name}'. "
            "Ask the orchestrator/user to set it in the container .env."
        )
    return value


def _build_dsn() -> str:
    """
    Build DSN from the standardized database env vars.

    Uses:
      - POSTGRES_URL (optional full DSN; if provided, it wins)
      - POSTGRES_USER, POSTGRES_PASSWORD, POSTGRES_DB, POSTGRES_PORT
    """
    url = os.getenv("POSTGRES_URL")
    if url:
        # Assume it is a valid libpq connection string / URL
        return url

    user = _required_env("POSTGRES_USER")
    password = _required_env("POSTGRES_PASSWORD")
    db = _required_env("POSTGRES_DB")
    port = _required_env("POSTGRES_PORT")

    # Host is always localhost for this mono-workspace environment.
    host = os.getenv("POSTGRES_HOST", "localhost")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


_POOL: Optional[ThreadedConnectionPool] = None


# PUBLIC_INTERFACE
def init_db_pool() -> None:
    """Initialize the global PostgreSQL connection pool."""
    global _POOL
    if _POOL is not None:
        return

    dsn = _build_dsn()
    # Conservative pool sizes for a small FastAPI service.
    _POOL = ThreadedConnectionPool(
        minconn=int(os.getenv("DB_POOL_MIN", "1")),
        maxconn=int(os.getenv("DB_POOL_MAX", "10")),
        dsn=dsn,
    )


@contextmanager
def _get_conn():
    if _POOL is None:
        init_db_pool()
    assert _POOL is not None
    conn = _POOL.getconn()
    try:
        yield conn
    finally:
        _POOL.putconn(conn)


def _dict_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


# PUBLIC_INTERFACE
def fetch_one(query: str, params: Optional[Sequence[Any]] = None) -> Optional[Dict[str, Any]]:
    """Fetch a single row as a dict, or None."""
    with _get_conn() as conn:
        with _dict_cursor(conn) as cur:
            cur.execute(query, params or [])
            row = cur.fetchone()
            return dict(row) if row else None


# PUBLIC_INTERFACE
def fetch_all(query: str, params: Optional[Sequence[Any]] = None) -> List[Dict[str, Any]]:
    """Fetch all rows as dicts."""
    with _get_conn() as conn:
        with _dict_cursor(conn) as cur:
            cur.execute(query, params or [])
            rows = cur.fetchall()
            return [dict(r) for r in rows]


# PUBLIC_INTERFACE
def execute(query: str, params: Optional[Sequence[Any]] = None) -> int:
    """Execute a statement (INSERT/UPDATE/DELETE). Returns affected rowcount."""
    with _get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(query, params or [])
            affected = cur.rowcount
            conn.commit()
            return affected


# PUBLIC_INTERFACE
def execute_returning_one(query: str, params: Optional[Sequence[Any]] = None) -> Dict[str, Any]:
    """Execute a statement with RETURNING and return the first row as dict."""
    with _get_conn() as conn:
        with _dict_cursor(conn) as cur:
            cur.execute(query, params or [])
            row = cur.fetchone()
            if not row:
                conn.rollback()
                raise RuntimeError("Expected one row returned, got none.")
            conn.commit()
            return dict(row)
