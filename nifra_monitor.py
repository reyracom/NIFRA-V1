# nifra_monitor.py
#!/usr/bin/env python3
import json
import os
import glob
from datetime import datetime, timezone
import argparse
import matplotlib.pyplot as plt
import numpy as np

def load_memory_buffer():
    """Load and analyze memory buffer"""
    if not os.path.exists("trainer/memory_buffer.jsonl"):
        print("Memory buffer not found")
        return {}
    
    entries = []
    with open("trainer/memory_buffer.jsonl", "r") as f:
        for line in f:
            try:
                entries.append(json.loads(line))
            except:
                pass
    
    return {
        "count": len(entries),
        "entries": entries,
        "last_update": entries[-1]["timestamp"] if entries else "Never"
    }

def load_results():
    """Load and analyze results files"""
    results_files = sorted(glob.glob("logs/results_*.json"))
    all_results = []
    
    for file_path in results_files:
        try:
            with open(file_path, "r") as f:
                results = json.load(f)
                if isinstance(results, list):
                    all_results.extend(results)
                else:
                    all_results.append(results)
        except:
            pass
    
    return {
        "count": len(all_results),
        "results": all_results,
        "files": len(results_files)
    }

def load_state_context():
    """Load state context"""
    if not os.path.exists("simulator/state_context.json"):
        return {}
    
    try:
        with open("simulator/state_context.json", "r") as f:
            return json.load(f)
    except:
        return {}

def analyze_learning():
    """Analyze learning progress"""
    memory = load_memory_buffer()
    results = load_results()
    state = load_state_context()
    
    print("=== NIFRA Learning Monitor ===\n")
    
    # Memory statistics
    print(f"Memory Buffer: {memory.get('count', 0)} entries")
    print(f"Last Update: {memory.get('last_update', 'Never')}")
    
    # Results statistics
    print(f"\nResults: {results.get('count', 0)} entries in {results.get('files', 0)} files")
    
    # Framework detection
    frameworks = state.get("frameworks", {})
    print(f"\nDetected Frameworks: {len(frameworks)}")
    for domain, fw in frameworks.items():
        print(f"  - {domain}: {fw.get('name', 'unknown')} (confidence: {fw.get('confidence', 'unknown')})")
    
    # Vulnerabilities
    vulns = state.get("vulnerabilities", [])
    print(f"\nVulnerabilities Found: {len(vulns)}")
    
    # Analyze rewards
    if results.get("results"):
        rewards = [r.get("reward", 0) for r in results["results"] if "reward" in r]
        if rewards:
            print(f"\nRewards Statistics:")
            print(f"  - Average: {sum(rewards)/len(rewards):.4f}")
            print(f"  - Min: {min(rewards):.4f}")
            print(f"  - Max: {max(rewards):.4f}")
            
            # Trend analysis
            if len(rewards) > 1:
                z = np.polyfit(range(len(rewards)), rewards, 1)
                if z[0] > 0:
                    print(f"  - Trend: Positive (learning effectively)")
                elif z[0] < 0:
                    print(f"  - Trend: Negative (may need more diverse targets)")
                else:
                    print(f"  - Trend: Flat (no significant learning)")
    
    # Learning improvement suggestions
    print("\nLearning Improvement Suggestions:")
    
    if memory.get("count", 0) < 10:
        print("  - Run more tests to build memory buffer")
    
    if not frameworks:
        print("  - Test against sites with identifiable frameworks")
    
    if vulns:
        print("  - Successful strategies found! Continue using similar patterns")
    else:
        print("  - No vulnerabilities found yet, try different payload strategies")
    
    return {
        "memory": memory,
        "results": results,
        "state": state
    }

def plot_learning_curve(data, save_path="nifra_learning_curve.png"):
    """Plot learning curve based on rewards"""
    rewards = []
    iterations = []
    
    if not data["results"]["results"]:
        print("No result data available for plotting")
        return
    
    for i, result in enumerate(data["results"]["results"]):
        if "reward" in result:
            rewards.append(result["reward"])
            iterations.append(i+1)
    
    if not rewards:
        print("No reward data available for plotting")
        return
    
    plt.figure(figsize=(10, 6))
    plt.plot(iterations, rewards, 'ro-')
    plt.title('NIFRA Learning Progress: Reward Evolution')
    plt.xlabel('Test Iteration')
    plt.ylabel('Reward Value')
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Adding trendline
    z = np.polyfit(iterations, rewards, 1)
    p = np.poly1d(z)
    plt.plot(iterations, p(iterations), "b--", alpha=0.7)
    
    # Showing trend direction
    if z[0] > 0:
        trend = "Positive trend: NIFRA is learning!"
    elif z[0] < 0:
        trend = "Negative trend: NIFRA might need more diverse targets"
    else:
        trend = "Flat trend: No significant learning detected"
    
    plt.annotate(trend, xy=(0.05, 0.95), xycoords='axes fraction', 
                fontsize=10, ha='left', va='top',
                bbox=dict(boxstyle='round,pad=0.5', fc='yellow', alpha=0.5))
    
    plt.savefig(save_path)
    print(f"Learning curve saved to '{save_path}'")

def main():
    parser = argparse.ArgumentParser(description="NIFRA Learning Monitor")
    parser.add_argument("--plot", action="store_true", help="Generate learning curve plot")
    args = parser.parse_args()
    
    data = analyze_learning()
    
    if args.plot:
        try:
            plot_learning_curve(data)
        except Exception as e:
            print(f"Error generating plot: {str(e)}")
    
    print("\nRun with --plot to generate learning curve visualization")

if __name__ == "__main__":
    main()
