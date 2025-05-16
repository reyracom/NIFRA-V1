# main.py
import json
import time
import argparse
from datetime import datetime, timezone
import asyncio
import os
import logging
import sys
import requests
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress warnings related to unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add path to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Import from correct submodules
from agents.agent_controller import run_cycle
from simulator.state_tracker import StateTracker

# Setup logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/main.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NIFRA-Main')

tracker = StateTracker()

def upload_results_to_server(results, target_url, upload_url=None, credentials=None):
    """
    Upload test results to server
    
    Args:
        results: Test results data
        target_url: Target URL tested
        upload_url: Endpoint URL for upload (default: reyralabs.com/upload-handler.php)
        credentials: (username, password) for authentication if required
    
    Returns:
        bool: True if successful, False if failed
    """
    try:
        # Default URL if not provided
        if not upload_url:
            upload_url = "https://reyralabs.com/upload-handler.php"
        
        # URL for result file
        result_file_url = "https://reyralabs.com/nifra-learning.json"
        
        # Prepare data to send
        upload_data = {
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "target": target_url,
            "results": results,
            "summary": {
                "total_tests": len(results),
                "average_reward": sum(r.get("reward", 0) for r in results) / len(results) if results else 0,
                "frameworks_detected": list(set(r.get("framework") for r in results if r.get("framework"))),
                "vulnerabilities": [r for r in results if r.get("evaluation", {}).get("status") == "SUCCESS"]
            }
        }
        
        # Headers
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "NIFRA Security Testing Framework"
        }
        
        logger.info(f"Uploading results to {upload_url}...")
        
        # Perform POST request with or without authentication
        if credentials:
            username, password = credentials
            response = requests.post(
                upload_url, 
                json=upload_data,
                headers=headers,
                auth=HTTPBasicAuth(username, password),
                verify=False  # Optional, use True in production if certificate is valid
            )
        else:
            response = requests.post(
                upload_url, 
                json=upload_data,
                headers=headers,
                verify=False  # Optional, use True in production if certificate is valid
            )
        
        # Check response status
        if response.status_code in [200, 201, 204]:
            logger.info(f"Results successfully uploaded to {result_file_url}")
            return True
        else:
            logger.error(f"Failed to upload results: HTTP {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        logger.error(f"Error uploading results: {str(e)}")
        return False

async def run_target(target_url, iterations=1, upload_options=None):
    """Run NIFRA on target URL with specified number of iterations"""
    # Use timezone.utc to avoid DeprecationWarning
    log_time = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join("logs", f"nifra_{log_time}.log")
    
    # Create a new logger specific to this run
    run_logger = logging.getLogger(f'NIFRA-Run-{log_time}')
    run_logger.setLevel(logging.INFO)
    
    # Add file handler
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter('%(message)s'))
    run_logger.addHandler(file_handler)
    
    # Add stream handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter('%(message)s'))
    run_logger.addHandler(stream_handler)

    def log(msg):
        """Log messages to both file and console"""
        logger.info(msg)
        run_logger.info(msg)

    log(f"[NIFRA] Starting production security testing on {target_url}")
    
    # Configure target
    target = {
        "name": "Target",
        "url": target_url,
        "enabled": True,
        "priority": 1,
        "type": "web",
        "scan_limit": 5
    }
    
    total_reward = 0
    results = []
    
    for i in range(iterations):
        log(f"\n[NIFRA] Iteration {i+1}/{iterations} for {target_url}")
        try:
            start_time = time.time()
            
            # Run NIFRA cycle
            result = await run_cycle(domain="web", url=target_url)
            
            # Collect results
            status = result.get("evaluation", {}).get("status", "FAILED")
            reward = result.get("reward", 0)
            total_reward += reward
            
            duration = time.time() - start_time
            results.append(result)
            
            log(f"[NIFRA] Iteration {i+1} completed in {duration:.2f} seconds")
            log(f"[NIFRA] Status: {status}")
            log(f"[NIFRA] Framework: {result.get('framework', 'Unknown')}")
            log(f"[NIFRA] Reward: {reward}")
            
            # Display evaluation summary
            if "evaluation" in result and "summary" in result["evaluation"]:
                log(f"[NIFRA] Summary: {result['evaluation']['summary']}")
            
            # Add pause to avoid rate limiting
            if i < iterations - 1:
                log("[NIFRA] Pausing before next iteration...")
                time.sleep(2)
                
        except Exception as e:
            log(f"[NIFRA] ERROR during iteration {i+1}: {str(e)}")
            import traceback
            log(f"[NIFRA] Error details: {traceback.format_exc()}")
    
    # Display overall summary
    summary = tracker.get_summary() if hasattr(tracker, 'get_summary') else {
        'total_injections': len(tracker.state.get('injections', [])),
        'total_vulnerabilities': len(tracker.state.get('vulnerabilities', []))
    }
    
    log("\n[NIFRA] Testing Summary")
    log(f"Total Injections: {summary.get('total_injections', 0)}")
    log(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
    
    # Count vulnerabilities by severity
    vulns = tracker.state.get('vulnerabilities', [])
    vulns_by_severity = {}
    for vuln in vulns:
        severity = vuln.get("severity", "unknown")
        vulns_by_severity[severity] = vulns_by_severity.get(severity, 0) + 1
    
    if vulns_by_severity:
        log("Vulnerability Breakdown:")
        for severity, count in vulns_by_severity.items():
            log(f"  {severity.upper()}: {count}")
    
    log(f"Average Reward: {total_reward/iterations if iterations > 0 else 0:.4f}")
    log("\n[NIFRA] Testing Completed")
    
    # Upload results if requested - AFTER the log summary
    if upload_options and upload_options.get('enabled'):
        log("[NIFRA] Uploading results to server...")
        upload_url = upload_options.get('url')
        credentials = upload_options.get('credentials')
        
        success = upload_results_to_server(results, target_url, upload_url, credentials)
        
        if success:
            log("[NIFRA] Results uploaded successfully to server")
        else:
            log("[NIFRA] Failed to upload results to server")
    
    # Close file handler explicitly
    for handler in run_logger.handlers:
        handler.close()
    run_logger.removeHandler(file_handler)
    run_logger.removeHandler(stream_handler)
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIFRA AI Security Testing")
    parser.add_argument("--target-url", help="URL to test", required=True)
    parser.add_argument("--iterations", help="Number of testing iterations", type=int, default=1)
    
    # Add arguments for upload
    parser.add_argument("--upload", action="store_true", help="Upload results to server")
    parser.add_argument("--upload-url", help="URL for uploading results (default: reyralabs.com/upload-handler.php)", 
                       default="https://reyralabs.com/upload-handler.php")
    parser.add_argument("--username", help="Username for upload authentication")
    parser.add_argument("--password", help="Password for upload authentication")
    
    args = parser.parse_args()

    # Validate URL
    target_url = args.target_url
    if not target_url.startswith(("http://", "https://")):
        target_url = "https://" + target_url
    
    iterations = max(1, args.iterations)  # Minimum 1 iteration
        
    print(f"[NIFRA] Starting security test against {target_url} ({iterations} iterations)")

    # Target configuration
    target_config = {
        "name": "Target URL",
        "url": target_url,
        "framework": "unknown",  # Will be detected
        "enabled": True,
        "priority": 1,
        "type": "web",
        "scan_limit": 5
    }

    # Save target configuration to file
    os.makedirs("sandbox", exist_ok=True)
    with open(os.path.join("sandbox", "target_config.json"), "w") as f:
        json.dump(target_config, f, indent=2)
    
    # Configure upload if requested
    upload_options = None
    if args.upload:
        upload_options = {
            'enabled': True,
            'url': args.upload_url
        }
        
        # Add credentials if provided
        if args.username and args.password:
            upload_options['credentials'] = (args.username, args.password)
        
        print(f"[NIFRA] Results will be uploaded to {upload_options['url']}")

    # Run testing
    results = asyncio.run(run_target(target_url, iterations, upload_options))
    
    # Save results to JSON file
    os.makedirs("logs", exist_ok=True)
    # Use timezone.utc to avoid DeprecationWarning
    result_time = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    result_file = os.path.join("logs", f"results_{result_time}.json")
    with open(result_file, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"[NIFRA] Results saved to {result_file}")
    
    # Display summary
    print(f"\n[NIFRA] Testing finished with {len(results)} iterations")
    
    # Display information about NIFRA's learning database
    try:
        with open("trainer/memory_buffer.jsonl") as f:
            memory_entries = sum(1 for _ in f)
        print(f"[NIFRA] Learning database now contains {memory_entries} entries")
        
        # Check if any significant vulnerabilities were detected
        if results and 'reward' in results[-1]:
            if results[-1]['reward'] > 0.5:
                print("[NIFRA] Significant vulnerabilities detected in the target!")
            elif results[-1]['reward'] > 0.2:
                print("[NIFRA] Some potential issues detected, but further testing recommended")
            else:
                print("[NIFRA] No significant vulnerabilities detected")
    except Exception as e:
        print(f"[NIFRA] Warning: Could not analyze learning database: {str(e)}")
    
    # Recommend next steps
    if iterations < 3:
        print("\n[NIFRA] Recommendation: For better learning, try running more iterations:")
        print(f"python3 main.py --target-url {target_url} --iterations 5")
    
    # Display upload info if used
    if args.upload:
        print(f"\n[NIFRA] Results have been uploaded to the server")
        print(f"[NIFRA] You can view the latest results at: https://reyralabs.com/nifra-learning.json")
