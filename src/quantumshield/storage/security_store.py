
"""
QuantumShield - Security Storage

Provides:
    - SQLite-backed replay protection
    - Atomic transfer claims
    - Transfer completion tracking
    - Security audit logging

Never stores passwords, private keys, plaintext files,
or cryptographic secrets.
"""

import sqlite3

from datetime import datetime, timedelta, timezone
from pathlib import Path


# =====================================================
# CONFIGURATION
# =====================================================

BASE_DIR = Path(__file__).resolve().parents[3]

DATA_DIR = BASE_DIR / "data"

DATABASE_PATH = DATA_DIR / "quantumshield.db"

CLAIM_TIMEOUT_MINUTES = 30


class TransferAlreadyProcessed(Exception):
    """Raised when a transfer ID has already been claimed."""


# =====================================================
# DATABASE INITIALIZATION
# =====================================================

def initialize_security_store():
    """Initialize SQLite storage and database tables."""

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    DATA_DIR.chmod(0o700)

    with sqlite3.connect(DATABASE_PATH, timeout=10) as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS processed_transfers (
                transfer_id TEXT PRIMARY KEY,
                recipient TEXT NOT NULL,
                package_sha256 TEXT NOT NULL,
                status TEXT NOT NULL
                    CHECK(status IN ('processing', 'completed')),
                claimed_at TEXT NOT NULL,
                completed_at TEXT
            )
        """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                username TEXT,
                transfer_id TEXT,
                mode TEXT,
                outcome TEXT NOT NULL,
                details TEXT
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp
            ON audit_events(timestamp)
        """)

    # Restrict access to the database file.
    if DATABASE_PATH.exists():
        DATABASE_PATH.chmod(0o600)


# =====================================================
# TIMESTAMP
# =====================================================

def _utc_now():
    return datetime.now(timezone.utc)


# =====================================================
# CLAIM TRANSFER
# =====================================================

def claim_transfer(
    transfer_id: str,
    recipient: str,
    package_sha256: str
) -> bool:
    """
    Atomically claim a transfer ID.

    Returns:
        True: Transfer is newly claimed.
        False: Transfer is already processing or completed.

    A stale processing claim can be reclaimed after
    CLAIM_TIMEOUT_MINUTES. Completed transfers cannot
    be reclaimed.
    """

    initialize_security_store()

    now = _utc_now()
    now_text = now.isoformat()

    stale_before = (
        now - timedelta(minutes=CLAIM_TIMEOUT_MINUTES)
    ).isoformat()

    with sqlite3.connect(
        DATABASE_PATH,
        timeout=10,
        isolation_level=None
    ) as connection:

        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute(
            """
            SELECT status, claimed_at
            FROM processed_transfers
            WHERE transfer_id = ?
            """,
            (transfer_id,)
        ).fetchone()

        if existing:

            status, claimed_at = existing

            if status == "completed":
                connection.rollback()
                return False

            if claimed_at >= stale_before:
                connection.rollback()
                return False

            # Recover an abandoned claim.
            connection.execute(
                """
                UPDATE processed_transfers
                SET recipient = ?,
                    package_sha256 = ?,
                    status = 'processing',
                    claimed_at = ?,
                    completed_at = NULL
                WHERE transfer_id = ?
                """,
                (
                    recipient,
                    package_sha256,
                    now_text,
                    transfer_id
                )
            )

        else:

            connection.execute(
                """
                INSERT INTO processed_transfers (
                    transfer_id,
                    recipient,
                    package_sha256,
                    status,
                    claimed_at
                )
                VALUES (?, ?, ?, 'processing', ?)
                """,
                (
                    transfer_id,
                    recipient,
                    package_sha256,
                    now_text
                )
            )

        connection.commit()

    return True


# =====================================================
# COMPLETE TRANSFER
# =====================================================

def complete_transfer(transfer_id: str):
    """Mark a successfully decrypted transfer as completed."""

    initialize_security_store()

    with sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    ) as connection:

        cursor = connection.execute(
            """
            UPDATE processed_transfers
            SET status = 'completed',
                completed_at = ?
            WHERE transfer_id = ?
              AND status = 'processing'
            """,
            (
                _utc_now().isoformat(),
                transfer_id
            )
        )

        if cursor.rowcount != 1:
            raise RuntimeError(
                "Unable to mark transfer as completed."
            )


# =====================================================
# RELEASE FAILED CLAIM
# =====================================================

def release_transfer_claim(transfer_id: str):
    """
    Release a processing claim after a failed operation.

    This allows a legitimate retry after correcting
    a password or supplying the correct key.
    """

    initialize_security_store()

    with sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    ) as connection:

        connection.execute(
            """
            DELETE FROM processed_transfers
            WHERE transfer_id = ?
              AND status = 'processing'
            """,
            (transfer_id,)
        )


# =====================================================
# AUDIT EVENT RECORDING
# =====================================================

def record_audit_event(
    event_type: str,
    outcome: str,
    username: str = None,
    transfer_id: str = None,
    mode: str = None,
    details: str = None
):
    """
    Record an application security event.

    Never pass passwords, private keys, plaintext,
    AES keys or other sensitive material in details.
    """

    initialize_security_store()

    safe_details = (
        str(details)[:300]
        if details is not None
        else None
    )

    with sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    ) as connection:

        connection.execute(
            """
            INSERT INTO audit_events (
                timestamp,
                event_type,
                username,
                transfer_id,
                mode,
                outcome,
                details
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                _utc_now().isoformat(),
                event_type,
                username,
                transfer_id,
                mode,
                outcome,
                safe_details
            )
        )


# =====================================================
# READ AUDIT EVENTS
# =====================================================

def get_audit_events(limit: int = 200):
    """Return the latest audit events."""

    if not isinstance(limit, int) or not 1 <= limit <= 1000:
        raise ValueError("Limit must be between 1 and 1000.")

    initialize_security_store()

    with sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    ) as connection:

        connection.row_factory = sqlite3.Row

        rows = connection.execute(
            """
            SELECT
                id,
                timestamp,
                event_type,
                username,
                transfer_id,
                mode,
                outcome,
                details
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        ).fetchall()

    return [dict(row) for row in rows]


# =====================================================
# TRANSFER STATUS
# =====================================================

def get_transfer_status(transfer_id: str):
    """Retrieve the current processing status."""

    initialize_security_store()

    with sqlite3.connect(
        DATABASE_PATH,
        timeout=10
    ) as connection:

        row = connection.execute(
            """
            SELECT status, recipient, claimed_at, completed_at
            FROM processed_transfers
            WHERE transfer_id = ?
            """,
            (transfer_id,)
        ).fetchone()

    if row is None:
        return None

    return {
        "status": row[0],
        "recipient": row[1],
        "claimed_at": row[2],
        "completed_at": row[3]
    }

