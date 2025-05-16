# memory_logger.py
import json
from datetime import datetime
import os

def save_to_buffer(task, payload, result, evaluation, fingerprint=None, path="trainer/memory_buffer.jsonl"):
    # Buat direktori jika belum ada
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "task": task,
        "payload": payload,
        "injected_field": result.get("injected_field"),
        "bypassed": result.get("bypassed"),
        "evaluation": evaluation,
        "status": result.get("status"),
        "output": result.get("output")[:200]  # Log pendek aja
    }

    # Tambahan hasil fingerprint jika tersedia
    if fingerprint:
        entry.update({
            "framework": fingerprint.get("framework"),
            "confidence": fingerprint.get("confidence"),
            "favicon_hash": fingerprint.get("favicon_hash"),
            "threat": fingerprint.get("threat"),
            "indicators": fingerprint.get("indicators", []),
            "redirected": fingerprint.get("redirected")
        })

    with open(path, "a") as f:
        f.write(json.dumps(entry) + "\n")
