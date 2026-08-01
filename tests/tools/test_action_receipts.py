def test_action_receipt_round_trip_is_idempotent():
    from tools.action_receipts import record_receipt, get_receipt, list_receipts

    first = record_receipt(
        action="orbit.pr11.verify",
        status="verified",
        scope="orbit",
        evidence=["ci:green", "audit:0 vulnerabilities"],
        idempotency_key="fc2c652",
    )
    second = record_receipt(
        action="orbit.pr11.verify",
        status="verified",
        scope="orbit",
        evidence=["ci:green"],
        idempotency_key="fc2c652",
    )
    assert second["receipt_id"] == first["receipt_id"]
    assert get_receipt(first["receipt_id"])["status"] == "verified"
    assert len(list_receipts(scope="orbit")) == 1


def test_action_receipt_keeps_failure_and_evidence():
    from tools.action_receipts import record_receipt, list_receipts

    record_receipt(action="send.email", status="blocked", scope="private", evidence=["no approval"])
    rows = list_receipts(scope="private")
    assert rows[0]["status"] == "blocked"
    assert rows[0]["evidence"] == ["no approval"]


def test_action_receipt_records_attribution_and_lineage():
    from tools.action_receipts import record_receipt

    row = record_receipt(
        action="deploy.preview",
        status="completed",
        scope="project-x",
        provenance_source="direct_human",
        evidence_kind="approval",
        evidence_ref="approval-123",
        originator="user-1",
        accountable_party="user-1",
        parent_receipt_id="receipt-parent",
    )

    assert row["provenance_source"] == "direct_human"
    assert row["evidence"] == ["approval"]
    assert row["evidence_kind"] == "approval"
    assert row["evidence_ref"] == "approval-123"
    assert row["originator"] == "user-1"
    assert row["accountable_party"] == "user-1"
    assert row["parent_receipt_id"] == "receipt-parent"


def test_action_receipt_strict_attribution_rejects_degraded_source():
    import pytest
    from tools.action_receipts import record_receipt

    with pytest.raises(ValueError, match="precise attribution"):
        record_receipt(
            action="deploy.production",
            status="requested",
            scope="project-x",
            provenance_source="owner_fallback",
            strict_attribution=True,
        )