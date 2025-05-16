import random

def update_strategy(evaluation, task, payload):
    strategy = {
        "success": evaluation.lower().startswith("success"),
        "framework": None,
        "next_action": "general_owasp_scan"
    }

    if strategy["success"]:
        print("[Strategy] Menandai kombinasi berhasil, memperkuat pendekatan ini.")
    else:
        print("[Strategy] Kombinasi gagal, akan mencoba strategi alternatif selanjutnya.")
        if random.random() > 0.7:
            print("  ↳ [Explore] Menjalankan strategi random untuk eksplorasi tak terduga.")
            strategy["next_action"] = random.choice([
                "inject_common_param", "fuzz_hidden_field", "try_cookie_attack"
            ])

    if isinstance(task, dict) and task.get("framework"):
        framework = task["framework"].lower()
        strategy["framework"] = framework
        print(f"[Strategy] Mengadaptasi strategi untuk framework: {framework}")

        if framework == "wordpress":
            print("  ↳ Fokus ke REST API, xmlrpc.php, dan plugin injection.")
            strategy["next_action"] = "focus_rest_api"
        elif framework == "laravel":
            print("  ↳ Uji CSRF bypass, route leakage, debug mode.")
            strategy["next_action"] = "bypass_csrf_and_debug"
        elif framework == "nextjs":
            print("  ↳ Periksa SSR leak, _next routes, props.")
            strategy["next_action"] = "ssr_prop_injection"
        elif framework == "rails":
            print("  ↳ Target controller dan filter auth.")
            strategy["next_action"] = "target_controller_filters"
        elif framework == "django":
            print("  ↳ Deteksi csrfmiddlewaretoken dan leak auth.")
            strategy["next_action"] = "csrf_token_attack"

    else:
        print("[Strategy] Tidak ada framework terdeteksi, gunakan strategi OWASP umum.")

    return strategy
