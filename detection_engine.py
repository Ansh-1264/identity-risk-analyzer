import json
from collections import defaultdict

LOG_FILE = "logs/security_logs.json"

def read_logs():
    logs = []

    try:
        with open(LOG_FILE, "r") as f:
            for line in f:
                logs.append(json.loads(line))
    except FileNotFoundError:
        print("No logs found.")

    return logs

def detect_brute_force(logs):

    user_activity = defaultdict(list)

    # Group logs by user
    for log in logs:
        username = log["username"]
        user_activity[username].append(log["event"])

    alerts = []

    for user, events in user_activity.items():

        failed_count = events.count("failed_login")
        lockout_count = events.count("accounts_lockout")

        # Detection login
        if failed_count >= 5 or lockout_count > 0:
            alerts.append({
                "user": user,
                "type": "Brute Force Attack",
                "severity": "HIGH",
                "failed_attempts": failed_count
            })

    return alerts


def main():
    logs = read_logs()

    alerts = detect_brute_force(logs)

    print("\n=== SECURITY ALERTS ===\n")

    if not alerts:
        print("no threats detected")
    else:
        for alert in alerts:
            print(f"ALERT: {alert['type']} detected for user {alert['user']}")
            print(f"Failed Attempts: {alert['failed_attempts']}")
            print(f" Severity: {alert['severity']}\n")


if __name__ == "__main__":
    main()


