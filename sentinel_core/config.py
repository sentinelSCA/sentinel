import os

# Change this later. For now keep it local/dev.
SENTINEL_SIGNING_SECRET = os.getenv("SENTINEL_SIGNING_SECRET", "dev-change-me-now")

# Contract + policy versions (your API promise)
API_CONTRACT_VERSION = "v1.1"
POLICY_VERSION = os.getenv("SENTINEL_POLICY_VERSION", "v1")

# Future hook placeholders
STAKING_ENABLED = os.getenv("SENTINEL_STAKING_ENABLED", "false").lower() == "true"
