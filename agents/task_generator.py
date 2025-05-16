import random

def generate_task_scenario(domain=None, framework=None):
    objectives = [
        "explore surface",
        "test for SQL injection",
        "check for XSS",
        "find authentication bypass",
        "analyze input validation",
        "evaluate CSRF exposure"
    ]
    objective_weights = [0.1, 0.2, 0.2, 0.15, 0.2, 0.15]

    target_types = ["web", "api", "mobile", "iot", "cloud"]
    target_vectors = ["input", "auth", "api", "upload", "session"]
    risk_levels = ["low", "medium", "high"]
    modes = ["default", "aggressive", "stealth"]

    if domain is None:
        domain = random.choice(target_types)

    objective = random.choices(objectives, weights=objective_weights, k=1)[0]

    task = {
        "domain": domain,
        "objective": objective,
        "risk": random.choice(risk_levels),
        "mode": random.choice(modes),
        "target_vector": random.choice(target_vectors)
    }

    if framework:
        task["framework"] = framework

    task["id"] = f"{objective.split()[0]}_{random.randint(1000,9999)}"

    print(f"[TaskGen] Generated task: {task}")
    return task

def generate_batch(n=10):
    return [generate_task_scenario() for _ in range(n)]
