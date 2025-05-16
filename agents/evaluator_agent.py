# agents/evaluator_agent.py
import requests
import json
import os
import random
import logging
import sys

# Tambahkan path ke Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logger = logging.getLogger('NIFRA-Evaluator')

def evaluate_result(context, model='openhermes'):
    """
    Evaluates the result of a security test.
    Falls back to local evaluation if model API is unavailable.
    """
    try:
        base_prompt = f"""[Evaluator]
Context: {context}
Evaluate the security test result above.
Return a structured JSON with these fields:
- status: "SUCCESS", "FAILED", or "BLOCKED"
- score: 0.0-1.0 based on effectiveness
- summary: brief analysis
"""

        # Coba gunakan model API
        try:
            response = requests.post(
                'http://localhost:11434/api/generate',
                json={"model": model, "prompt": base_prompt, "stream": False},
                timeout=5
            )
            
            if response.status_code == 200:
                result_text = response.json().get('response', '').strip()
                # Handle case where the model doesn't return valid JSON
                if '{' in result_text and '}' in result_text:
                    json_str = result_text[result_text.find('{'):result_text.rfind('}')+1]
                    try:
                        return json.loads(json_str)
                    except:
                        pass
            
            # If API failed, fall back to local evaluation
            logger.warning("Model API failed, falling back to local evaluation")
        except:
            logger.warning("Model API unavailable, using local evaluation")
        
        # Local evaluation
        return _local_evaluate(context)
    
    except Exception as e:
        logger.error(f"Error in evaluation: {str(e)}")
        return {"status": "ERROR", "score": 0.0, "summary": f"Error in evaluation: {str(e)}"}

def _local_evaluate(context):
    """Local evaluation when API is unavailable"""
    # Parse the context to extract useful information
    task_info = {}
    payload = ""
    result_output = ""
    
    lines = context.split('\n')
    for line in lines:
        if line.startswith("Task:"):
            try:
                task_text = line[5:].strip()
                if task_text.startswith('{'):
                    task_info = json.loads(task_text)
                else:
                    task_info = {"text": task_text}
            except:
                task_info = {"text": line[5:].strip()}
        elif line.startswith("Payload:"):
            payload = line[8:].strip()
        elif line.startswith("Output:"):
            result_output = line[7:].strip()
    
    # Simple heuristic analysis
    score = 0.0
    status = "FAILED"
    summary = "No significant findings detected."
    
    # Check for signs of success in the output
    success_indicators = [
        "reflection", "syntax error", "exception", "warning", 
        "undefined", "invalid", "unexpected", "sql", "error",
        "mysql", "failed", "alert(", "<script>", "flag{"
    ]
    
    if any(indicator in result_output.lower() for indicator in success_indicators):
        status = "SUCCESS"
        score = random.uniform(0.6, 0.9)
        summary = "Potential vulnerability detected. The payload appears to have triggered an error or unusual response."
    
    # Check for signs of being blocked
    blocked_indicators = [
        "forbidden", "403", "blocked", "waf", "firewall", 
        "security", "denied", "permission", "unauthorized"
    ]
    
    if any(indicator in result_output.lower() for indicator in blocked_indicators):
        status = "BLOCKED"
        score = random.uniform(0.1, 0.3)
        summary = "The request appears to have been blocked by security controls."
    
    # If neither success nor blocked indicators are found
    if status == "FAILED":
        score = random.uniform(0.0, 0.4)
        summary = "No clear vulnerability detected. The target handled the input appropriately."
    
    return {
        "status": status,
        "score": round(score, 2),
        "summary": summary
    }
