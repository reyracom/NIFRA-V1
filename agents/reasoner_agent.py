def reason_task_objective(task):
    reasoning = []

    # Analisa dasar dari deskripsi task
    if isinstance(task, dict):
        domain = task.get("domain", "web")
        objective = task.get("objective", "explore surface")
        framework = task.get("framework")

        reasoning.append(f"Domain: {domain}")
        reasoning.append(f"Objective: {objective}")

        if framework:
            reasoning.append(f"Detected framework: {framework}")
            if framework.lower() == "wordpress":
                reasoning.append("Likely REST API or plugin-based injection surface.")
            elif framework.lower() == "laravel":
                reasoning.append("Consider CSRF, route fuzzing, and debug exposure.")
            elif framework.lower() == "nextjs":
                reasoning.append("Check SSR data leaks via _next or JSON payload override.")
            elif framework.lower() == "rails":
                reasoning.append("Review controller naming patterns and auth filters.")
        else:
            reasoning.append("No framework detected, assume general OWASP testing.")
    else:
        reasoning.append("No structured task found, defaulting to generic web reasoning.")

    return " | ".join(reasoning)
