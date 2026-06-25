import requests
import json
import hashlib
import hmac
import base64
import datetime
import random
import time
from dotenv import load_dotenv
import os

load_dotenv()

WORKSPACE_ID = ("b7c74351-c2c6-42ae-b8e6-4dc78eca01ba")
WORKSPACE_KEY = ("tfc7kQYzysIdJg3TQSiRwhfyvn0EadptlWdwjEhnKLXYm211nz2rOUC394AM+sa3JiHOmMzuVADq97skJSPW6Q==")
LOG_TYPE = "SimulatedSecurityEvents"

# Sample data pools
USERS = [
    "nithin.jangu@contoso.com",
    "john.smith@contoso.com",
    "sarah.jones@contoso.com",
    "admin@contoso.com"
]

MALICIOUS_IPS = ["185.220.101.45", "194.165.16.11", "45.142.212.100"]
CLEAN_IPS     = ["192.168.1.10", "10.0.0.5", "172.16.0.20"]
COUNTRIES     = ["GB", "US", "RU", "CN", "DE", "NG"]


def build_signature(date, content_length):
    x_headers     = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    bytes_to_hash  = string_to_hash.encode("utf-8")
    decoded_key    = base64.b64decode(WORKSPACE_KEY)
    encoded_hash   = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {WORKSPACE_ID}:{encoded_hash}"


def post_logs(body):
    rfc1123date    = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    signature      = build_signature(rfc1123date, content_length)
    uri = f"https://{WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"
    headers = {
        "Content-Type":  "application/json",
        "Authorization": signature,
        "Log-Type":      LOG_TYPE,
        "x-ms-date":     rfc1123date,
    }
    response = requests.post(uri, data=body, headers=headers)
    return response.status_code


def simulate_brute_force():
    """Simulate 15 failed logins from a suspicious IP — triggers Rule 1"""
    user   = random.choice(USERS)
    bad_ip = random.choice(MALICIOUS_IPS)
    events = []
    for _ in range(15):
        events.append({
            "EventType":          "FailedLogin",
            "UserPrincipalName":  user,
            "IPAddress":          bad_ip,
            "Country":            "RU",
            "ResultDescription":  "Invalid password",
            "TimeGenerated":      datetime.datetime.utcnow().isoformat()
        })
    return events


def simulate_impossible_travel():
    """Simulate logins from 2 different countries in same hour — triggers Rule 2"""
    user   = random.choice(USERS)
    events = []
    for country, ip in [("GB", "192.168.1.10"), ("CN", "45.142.212.100")]:
        events.append({
            "EventType":         "SuccessfulLogin",
            "UserPrincipalName": user,
            "IPAddress":         ip,
            "Country":           country,
            "TimeGenerated":     datetime.datetime.utcnow().isoformat()
        })
    return events


def simulate_privilege_escalation():
    """Simulate a user being assigned Global Admin — triggers Rule 3"""
    return [{
        "EventType":     "RoleAssignment",
        "ActorUPN":      random.choice(USERS),
        "TargetUPN":     "new.admin@contoso.com",
        "TargetRole":    "Global Administrator",
        "TimeGenerated": datetime.datetime.utcnow().isoformat()
    }]


# ── Main loop ──────────────────────────────────────────────────────────────
scenarios = {
    "Brute Force":           simulate_brute_force,
    "Impossible Travel":     simulate_impossible_travel,
    "Privilege Escalation":  simulate_privilege_escalation,
}

print("Starting log simulator — sending events to Azure Sentinel...")
print(f"Workspace ID: {WORKSPACE_ID[:8]}...")
print()

for name, fn in scenarios.items():
    events = fn()
    body   = json.dumps(events)
    status = post_logs(body)
    if status == 200:
        print(f"[OK]  {name} — {len(events)} event(s) sent")
    else:
        print(f"[ERR] {name} — HTTP {status}")
    time.sleep(1)

print()
print("Done. Wait 5-10 minutes then check Sentinel Logs with:")
print("  SimulatedSecurityEvents_CL | take 20")
