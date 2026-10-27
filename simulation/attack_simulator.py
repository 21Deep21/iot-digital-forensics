
import time
import requests

BASE_URL = "http://127.0.0.1:5000"


def run_simulation():
    print("\n=== ADF ATTACK SIMULATION ===")

    steps = [
        ("Phishing link clicked", "/verify"),
        ("Dummy payload downloaded", "/payload"),
    ]

    for description, endpoint in steps:
        response = requests.get(
            BASE_URL + endpoint,
            timeout=5
        )
        response.raise_for_status()
        print(f"[OK] {description}: HTTP {response.status_code}")
        time.sleep(2)

    print("\nStarting simulated C2 beaconing...")

    for number in range(1, 6):
        response = requests.get(
            BASE_URL + "/c2/checkin",
            timeout=5
        )
        response.raise_for_status()
        print(f"[BEACON {number}/5] HTTP {response.status_code}")

        if number < 5:
            time.sleep(3)

    print("\nSimulation completed successfully.")


if __name__ == "__main__":
    run_simulation()
