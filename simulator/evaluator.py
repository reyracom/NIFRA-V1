import re

def evaluate_result(context):
    output = context.split("Output:")[-1].strip().lower()
    result = {"status": "FAILURE", "score": 0.0, "summary": "No indication of successful exploitation"}

    if re.search(r"flag\{[a-z0-9_-]+\}", output):
        result.update({"status": "SUCCESS", "score": 1.0, "summary": "Flag pattern detected in output"})
        return result

    if any(k in output for k in ["success", "bypass", "exploited", "rooted"]):
        result.update({"status": "SUCCESS", "score": 1.0, "summary": "Exploit likely succeeded"})
        return result

    if any(k in output for k in ["403", "denied", "blocked", "invalid token"]):
        result.update({"status": "BLOCKED", "score": 0.2, "summary": "Target has some protection in place"})
        return result

    if "error" in output and "bypass" in output:
        result.update({"status": "POTENTIAL", "score": 0.6, "summary": "Error exploited to bypass check"})
        return result

    if "error" in output or "exception" in output:
        result.update({"status": "ERROR", "score": 0.4, "summary": "Target may be unstable or vulnerable"})
        return result

    if len(output) < 20:
        result.update({"status": "NO RESPONSE", "score": 0.1, "summary": "Insufficient output returned"})
        return result

    return result
