# sentinel_rules/core_rules.py

HIGH_RISK_COMMANDS = [
    "rm -rf /",
    "mkfs",
    "shutdown",
    "reboot",
    "sudo reboot",
]

MEDIUM_RISK_KEYWORDS = [
    "sudo",
    "chmod",
    "chown",
    "apt install",
]
