import requests

def generate_defense(task, model='mistral'): 
    if not isinstance(task, dict):
        return "[ERROR] Task is not structured properly"

    framework = task.get("framework")
    objective = task.get("objective")

    base_prompt = f"[Defense Planner]\nTask: {task}\nGenerate a security patch, rule, or mitigation suggestion to block the identified attack."

    if objective:
        base_prompt += f"\nObjective: {objective}"

    if framework:
        if framework.lower() == "wordpress":
            base_prompt += "\nTarget is WordPress. Suggest hardening plugin filters and REST API token checks."
        elif framework.lower() == "laravel":
            base_prompt += "\nTarget is Laravel. Add CSRF validation, disable debug, and limit route exposure."
        elif framework.lower() == "nextjs":
            base_prompt += "\nTarget is Next.js. Sanitize SSR inputs and validate JSON overrides."
        elif framework.lower() == "rails":
            base_prompt += "\nTarget is Rails. Use strong parameter filters and controller auth guards."
        elif framework.lower() == "django":
            base_prompt += "\nTarget is Django. Enable CSRF middleware, lock admin, and audit user inputs."

    response = requests.post(
        'http://localhost:11434/api/generate',
        json={"model": model, "prompt": base_prompt, "stream": False}
    )

    if response.status_code != 200:
        return f"[ERROR] Model API returned {response.status_code}"

    return response.json().get('response', '').strip()
