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