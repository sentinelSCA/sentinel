from sentinel_rules.policy_v2 import evaluate_command_v2


def test_root_delete_patterns():
    dangerous = [
        "rm -rf /",
        "rm -rf /*",
        "rm -f /",
        "rm -f /*",
    ]

    for cmd in dangerous:
        decision, risk, score, reason = evaluate_command_v2(cmd, 0)
        assert decision == "deny"
        assert risk == "high"


def test_safe_file_delete():
    decision, risk, score, reason = evaluate_command_v2(
        "rm -f /home/user/file.txt",
        0,
    )

    assert decision == "allow"
    assert risk == "low"

def test_hard_deny_cannot_be_overridden_by_reputation():
    decision, risk, score, reason = evaluate_command_v2(
        "rm -rf /",
        100  # absurdly high reputation
    )

    assert decision == "deny"
    assert risk == "high"
