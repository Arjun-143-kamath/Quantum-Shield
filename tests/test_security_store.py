
import sqlite3

import quantumshield.storage.security_store as store

import pytest

import quantumshield.crypto.key_manager as classical_manager
import quantumshield.crypto.pqc_key_manager as pqc_manager
import quantumshield.transfer.service as transfer_service

from quantumshield.storage.security_store import (
    TransferAlreadyProcessed
)

@pytest.mark.parametrize(
    "mode",
    ["classical", "pqc"]
)
def test_service_rejects_replayed_transfer(
    tmp_path,
    monkeypatch,
    mode
):
    """Verify replay prevention through the real transfer service."""

    data_directory = tmp_path / "data"
    keys_directory = data_directory / "keys"

    # Redirect all application storage to temporary locations.
    monkeypatch.setattr(
        transfer_service,
        "BASE_DIR",
        tmp_path
    )

    monkeypatch.setattr(
        transfer_service,
        "INCOMING_DIR",
        data_directory / "incoming"
    )

    monkeypatch.setattr(
        transfer_service,
        "OUTGOING_DIR",
        data_directory / "outgoing"
    )

    monkeypatch.setattr(
        classical_manager,
        "KEYS_DIR",
        keys_directory
    )

    monkeypatch.setattr(
        pqc_manager,
        "KEYS_DIR",
        keys_directory
    )

    monkeypatch.setattr(
        store,
        "DATA_DIR",
        data_directory
    )

    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        data_directory / "quantumshield.db"
    )

    # Initialize identities for the selected mode.
    if mode == "classical":

        transfer_service.initialize_user(
            "alice",
            "AliceSecurePassword123!"
        )

        transfer_service.initialize_user(
            "bob",
            "BobSecurePassword123!"
        )

    else:

        transfer_service.initialize_pqc_user(
            "alice",
            "AliceSecurePassword123!"
        )

        transfer_service.initialize_pqc_user(
            "bob",
            "BobSecurePassword123!"
        )

    # Alice sends a file to Bob.
    sent = transfer_service.send_file(
        file_data=b"QuantumShield replay protection test",
        filename="replay_test.txt",
        sender="alice",
        recipient="bob",
        sender_password="AliceSecurePassword123!",
        mode=mode
    )

    received_directory = data_directory / "received"

    # First reception must succeed.
    result = transfer_service.receive_file(
        sent["package_path"],
        "bob",
        "BobSecurePassword123!",
        str(received_directory)
    )

    assert result["signature_verified"] is True
    assert result["integrity_verified"] is True

    assert (
        received_directory / "replay_test.txt"
    ).read_bytes() == b"QuantumShield replay protection test"

    # The same transfer must now be rejected.
    with pytest.raises(TransferAlreadyProcessed):

        transfer_service.receive_file(
            sent["package_path"],
            "bob",
            "BobSecurePassword123!",
            str(received_directory)
        )


def test_service_rejects_oversized_file():

    from quantumshield.transfer.service import (
        _validate_transfer_input,
        MAX_TRANSFER_FILE_BYTES
    )

    oversized_data = b"x" * (MAX_TRANSFER_FILE_BYTES + 1)

    with pytest.raises(ValueError):

        _validate_transfer_input(
            oversized_data,
            "large_file.bin",
            "alice",
            "bob"
        )


def configure_test_database(tmp_path, monkeypatch):

    monkeypatch.setattr(
        store,
        "DATA_DIR",
        tmp_path
    )

    monkeypatch.setattr(
        store,
        "DATABASE_PATH",
        tmp_path / "quantumshield_test.db"
    )

    store.initialize_security_store()


def test_claim_transfer(tmp_path, monkeypatch):

    configure_test_database(tmp_path, monkeypatch)

    result = store.claim_transfer(
        "a" * 32,
        "bob",
        "b" * 64
    )

    assert result is True


def test_duplicate_transfer_claim(tmp_path, monkeypatch):

    configure_test_database(tmp_path, monkeypatch)

    transfer_id = "a" * 32

    first = store.claim_transfer(
        transfer_id,
        "bob",
        "b" * 64
    )

    second = store.claim_transfer(
        transfer_id,
        "bob",
        "b" * 64
    )

    assert first is True
    assert second is False


def test_completed_transfer_cannot_be_replayed(
    tmp_path,
    monkeypatch
):

    configure_test_database(tmp_path, monkeypatch)

    transfer_id = "c" * 32

    store.claim_transfer(
        transfer_id,
        "bob",
        "d" * 64
    )

    store.complete_transfer(transfer_id)

    replay = store.claim_transfer(
        transfer_id,
        "bob",
        "d" * 64
    )

    assert replay is False

    status = store.get_transfer_status(transfer_id)

    assert status["status"] == "completed"


def test_failed_transfer_can_be_retried(
    tmp_path,
    monkeypatch
):

    configure_test_database(tmp_path, monkeypatch)

    transfer_id = "e" * 32

    store.claim_transfer(
        transfer_id,
        "bob",
        "f" * 64
    )

    store.release_transfer_claim(transfer_id)

    retry = store.claim_transfer(
        transfer_id,
        "bob",
        "f" * 64
    )

    assert retry is True


def test_expired_claim_can_be_recovered(
    tmp_path,
    monkeypatch
):

    configure_test_database(tmp_path, monkeypatch)

    transfer_id = "1" * 32

    store.claim_transfer(
        transfer_id,
        "bob",
        "2" * 64
    )

    # Simulate an abandoned operation from one hour ago.
    with sqlite3.connect(store.DATABASE_PATH) as connection:

        connection.execute(
            """
            UPDATE processed_transfers
            SET claimed_at = ?
            WHERE transfer_id = ?
            """,
            ("2000-01-01T00:00:00+00:00", transfer_id)
        )

    recovered = store.claim_transfer(
        transfer_id,
        "bob",
        "3" * 64
    )

    assert recovered is True

    status = store.get_transfer_status(transfer_id)

    assert status["status"] == "processing"


def test_audit_event_recording(tmp_path, monkeypatch):

    configure_test_database(tmp_path, monkeypatch)

    store.record_audit_event(
        event_type="transfer_received",
        outcome="success",
        username="bob",
        transfer_id="a" * 32,
        mode="pqc",
        details="Test transfer completed"
    )

    events = store.get_audit_events()

    assert len(events) == 1

    assert events[0]["event_type"] == "transfer_received"
    assert events[0]["username"] == "bob"
    assert events[0]["outcome"] == "success"


def test_audit_details_are_truncated(tmp_path, monkeypatch):

    configure_test_database(tmp_path, monkeypatch)

    store.record_audit_event(
        event_type="test",
        outcome="failure",
        details="X" * 500
    )

    events = store.get_audit_events()

    assert len(events[0]["details"]) == 300

