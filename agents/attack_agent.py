import requests

def generate_attack(task, model='deepseek-coder'):
    if not isinstance(task, dict):
        return "[ERROR] Task is not structured properly"

    framework = task.get("framework")
    objective = task.get("objective")

    base_prompt = f"[Attack Planner]\nTask: {task}\nGenerate a precise exploit payload (XSS, SQLi, etc)."

    if objective:
        base_prompt += f"\nObjective: {objective}"

    if framework:
        if framework.lower() == "wordpress":
            base_prompt += "\nTarget is WordPress. Focus on wp-json, REST API, and common plugin vulnerabilities."
        elif framework.lower() == "laravel":
            base_prompt += "\nTarget is Laravel. Explore CSRF tokens, debug endpoints, and route fuzzing."
        elif framework.lower() == "nextjs":
            base_prompt += "\nTarget is Next.js. Try SSR leak, _next/ routes, or JSON override."
        elif framework.lower() == "rails":
            base_prompt += "\nTarget is Ruby on Rails. Look for route exploits and mass assignment."
        elif framework.lower() == "django":
            base_prompt += "\nTarget is Django. Probe csrfmiddlewaretoken and exposed admin routes."

    response = requests.post(
        'http://localhost:11434/api/generate',
        json={"model": model, "prompt": base_prompt, "stream": False}
    )

    if response.status_code != 200:
        return f"[ERROR] Model API returned {response.status_code}"

    return response.json().get('response', '').strip()
