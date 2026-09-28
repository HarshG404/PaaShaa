"""Central configuration. Override the data dir with the PAASHAA_HOME env var."""
import os

HOME = os.environ.get("PAASHAA_HOME") or os.path.join(os.path.expanduser("~"), ".paashaa")
os.makedirs(HOME, exist_ok=True)
try:
    os.chmod(HOME, 0o700)
except OSError:
    pass

DB_PATH = os.path.join(HOME, "vault.db")
KEY_PATH = os.path.join(HOME, "secret.key")
LOG_PATH = os.path.join(HOME, "paashaa.log")
USE_KEYRING = os.environ.get("PAASHAA_USE_KEYRING") == "1"   # store vault key in the OS keyring

OTP_TTL = 600            # seconds (10 minutes)
OTP_MAX_TRIES = 5
MAX_LOGIN_FAILS = 5
LOCKOUT_SECS = 60
AUTOLOCK_SECS = 300      # auto-logout after 5 idle minutes
CLIPBOARD_CLEAR_SECS = 30
PASSWORD_MAX_AGE_DAYS = 90
SCHEDULER_POLL_SECS = 30
