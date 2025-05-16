import subprocess
import os
import json

SANDBOX_CONFIG_PATH = "sandbox/target_config.json"
DOCKER_COMPOSE_FILE = "sandbox/docker-compose.yml"

# Load target list from JSON config
def load_targets():
    if not os.path.exists(SANDBOX_CONFIG_PATH):
        raise FileNotFoundError("Missing sandbox/target_config.json")
    with open(SANDBOX_CONFIG_PATH) as f:
        return json.load(f)

# Launch sandbox using docker-compose
def start_sandbox():
    print("[Sandbox] Starting DVWA/Juice Shop environment...")
    subprocess.run(["docker-compose", "-f", DOCKER_COMPOSE_FILE, "up", "-d"])

# Stop and clean sandbox
def stop_sandbox():
    print("[Sandbox] Stopping containers...")
    subprocess.run(["docker-compose", "-f", DOCKER_COMPOSE_FILE, "down"])

# Print current target info
def list_targets():
    try:
        targets = load_targets()
        print("[Sandbox] Configured Targets:")
        for target in targets.get("targets", []):
            print(f" - {target['name']} @ {target['url']}")
    except Exception as e:
        print(f"[Sandbox] Failed to load targets: {e}")

if __name__ == "__main__":
    list_targets()
    start_sandbox()
