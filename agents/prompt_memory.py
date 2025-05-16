# agents/prompt_memory.py
import json
from datetime import datetime
import os

MEMORY_FILE = "trainer/prompt_memory.jsonl"

def store_prompt(prompt, response, score=1.0):
    # Buat direktori jika tidak ada
    os.makedirs(os.path.dirname(MEMORY_FILE), exist_ok=True)
    
    entry = {
        "timestamp": datetime.now().isoformat(),
        "prompt": prompt,
        "response": response,
        "score": score
    }
    with open(MEMORY_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

def get_top_prompts(limit=5):
    try:
        with open(MEMORY_FILE) as f:
            lines = [json.loads(line) for line in f]
        return sorted(lines, key=lambda x: x['score'], reverse=True)[:limit]
    except FileNotFoundError:
        return []
