import os
import urllib.request

print("=== ENV CHECK ===")
print("SENTINEL_URL =", os.getenv("SENTINEL_URL"))
print("API_BASE_URL =", os.getenv("API_BASE_URL"))
print("REDIS_URL =", os.getenv("REDIS_URL"))

print("\n=== HEALTH CHECK ===")
try:
    health = urllib.request.urlopen(
        os.getenv("API_BASE_URL") + "/health",
        timeout=5
    ).read().decode()
    print("Health OK:", health)
except Exception as e:
    print("Health FAILED:", e)
