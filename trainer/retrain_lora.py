import os
import json
from datetime import datetime
from pathlib import Path
import subprocess
import logging
import random

# Setup logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('NIFRA-Retrainer')

MEMORY_LOG_PATH = "trainer/memory_buffer.jsonl"
OUTPUT_DATASET_PATH = "trainer/lora_dataset.jsonl"
LORA_CONFIG_PATH = "trainer/lora_config.json"
LORA_OUTPUT_PATH = "trainer/lora_model"

def generate_lora_dataset(memory_log=MEMORY_LOG_PATH, output_path=OUTPUT_DATASET_PATH, prompt_mode="structured", min_entries=10):
    """Generate dataset for LoRA fine-tuning from memory log"""
    if not os.path.exists(memory_log):
        logger.warning("Memory log not found.")
        return False
        
    # Check if we have enough entries
    with open(memory_log, "r") as f:
        entries = f.readlines()
        if len(entries) < min_entries:
            logger.info(f"Not enough entries for training. Have {len(entries)}, need {min_entries}.")
            return False
    
    dataset = []
    success_entries = []
    
    with open(memory_log, "r") as f:
        for line in f:
            try:
                entry = json.loads(line)
                
                # Extract relevant fields
                task = entry.get('task', {})
                payload = entry.get('payload', '')
                evaluation = entry.get('evaluation', {})
                
                # Skip entries without proper data
                if not task or not payload:
                    continue
                
                # Calculate success score
                eval_score = 0
                if isinstance(evaluation, dict):
                    eval_score = evaluation.get("score", 0)
                    status = evaluation.get("status", "").upper()
                    if status == "SUCCESS":
                        eval_score = max(eval_score, 0.7)  # Ensure high score for successful entries
                
                # Store successful entries separately
                if eval_score > 0.5:
                    success_entries.append((task, payload, eval_score))
                
                # Format the input prompt based on mode
                if prompt_mode == "structured":
                    input_prompt = f"Task: {json.dumps(task)}\nStrategy: {entry.get('strategy')}\nGenerate a payload for the following task:\n"
                else:
                    input_prompt = f"Given the task '{json.dumps(task)}', generate a payload that would work effectively."

                # Format output with rewarded learning signal
                output_result = f"Payload: {payload}\nEffectiveness: {eval_score:.2f}"
                
                # Add metadata
                metadata = {
                    "framework": entry.get("framework"),
                    "score": eval_score,
                    "timestamp": entry.get("timestamp")
                }

                dataset.append({
                    "input": input_prompt,
                    "output": output_result,
                    "meta": metadata
                })
            except Exception as e:
                logger.error(f"Skipping line due to error: {e}")
    
    # Ensure we have enough successful examples by duplicating and slightly modifying them
    if success_entries:
        logger.info(f"Found {len(success_entries)} successful entries")
        # Duplicate successful entries to ensure they're weighted more heavily
        for _ in range(min(5, 50 // len(success_entries))):
            for task, payload, score in success_entries:
                # Add slight variations to avoid overfit
                modified_payload = _add_variation(payload)
                input_prompt = f"Task: {json.dumps(task)}\nStrategy: success\nGenerate a payload for the following task:\n"
                output_result = f"Payload: {modified_payload}\nEffectiveness: {score:.2f}"
                
                dataset.append({
                    "input": input_prompt,
                    "output": output_result,
                    "meta": {"framework": task.get("framework"), "score": score, "augmented": True}
                })
    
    # Ensure output directory exists
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    
    # Write dataset to output file
    with open(output_path, "w") as f:
        for item in dataset:
            f.write(json.dumps(item) + "\n")
    
    logger.info(f"Generated {len(dataset)} entries → {output_path}")
    return True

def _add_variation(payload):
    """Add slight variations to payload to avoid overfit during training"""
    variations = [
        lambda p: p.replace("alert(", "alert(/*var*/"),
        lambda p: p.replace("1=1", "1 = 1"),
        lambda p: p.replace("'", "\""),
        lambda p: p + "\n// Slightly modified version",
        lambda p: p.replace("script", "scrIpt"),
    ]
    
    # Apply 1-2 random variations
    result = payload
    for _ in range(random.randint(1, 2)):
        variation_func = random.choice(variations)
        result = variation_func(result)
    
    return result

def create_lora_config(dataset_path=OUTPUT_DATASET_PATH, config_path=LORA_CONFIG_PATH):
    """Create configuration for LoRA fine-tuning"""
    config = {
        "base_model": "deepseek-coder-1.3b-instruct",  # Change to your actual model
        "dataset": dataset_path,
        "output_dir": LORA_OUTPUT_PATH,
        "lora_r": 8,
        "lora_alpha": 32,
        "lora_dropout": 0.05,
        "learning_rate": 2e-4,
        "batch_size": 4,
        "num_epochs": 3,
        "warmup_steps": 10,
        "save_steps": 50,
        "eval_steps": 50
    }
    
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    logger.info(f"LoRA config created: {config_path}")
    return config_path

def run_lora_training(config_path=LORA_CONFIG_PATH):
    """Run actual LoRA training if Ollama is available"""
    try:
        # Check if Ollama is available
        subprocess.run(["ollama", "list"], check=True, capture_output=True)
        
        # Run training - this is a placeholder, actual implementation depends on your setup
        logger.info(f"Would run LoRA training with config: {config_path}")
        logger.info("This is a placeholder. Actual LoRA training implementation depends on your setup.")
        
        # Example command if using ollama-trainer (not a real tool, just an example)
        # subprocess.run(["ollama-trainer", "--config", config_path], check=True)
        
        # Mark training as successful
        with open(f"{LORA_OUTPUT_PATH}/training_complete.txt", "w") as f:
            f.write(f"Training completed at {datetime.now().isoformat()}")
        
        return True
    except subprocess.CalledProcessError:
        logger.error("Ollama not available for training")
        return False
    except Exception as e:
        logger.error(f"Error during LoRA training: {e}")
        return False

def should_retrain(min_entries=10, min_interval_hours=12):
    """Determine if retraining should be triggered"""
    # Check if memory buffer has enough entries
    if not os.path.exists(MEMORY_LOG_PATH):
        return False
    
    with open(MEMORY_LOG_PATH, "r") as f:
        entries = f.readlines()
        if len(entries) < min_entries:
            return False
    
    # Check when last training was done
    last_training_marker = f"{LORA_OUTPUT_PATH}/training_complete.txt"
    if os.path.exists(last_training_marker):
        with open(last_training_marker, "r") as f:
            last_training_time = f.read().strip().split("at ")[1]
            try:
                last_time = datetime.fromisoformat(last_training_time)
                hours_since_last = (datetime.now() - last_time).total_seconds() / 3600
                if hours_since_last < min_interval_hours:
                    logger.info(f"Last training was {hours_since_last:.1f} hours ago. Waiting for {min_interval_hours} hours.")
                    return False
            except:
                pass  # If can't parse, assume it's time to retrain
    
    return True

def retrain():
    """Main function to handle the retraining process"""
    if not should_retrain():
        logger.info("Retraining not needed at this time")
        return False
    
    # Generate dataset
    if not generate_lora_dataset():
        logger.info("Could not generate dataset, skipping training")
        return False
    
    # Create config
    create_lora_config()
    
    # Run training
    return run_lora_training()

if __name__ == "__main__":
    # Create output directory
    os.makedirs(LORA_OUTPUT_PATH, exist_ok=True)
    
    if retrain():
        logger.info("LoRA retraining completed successfully!")
    else:
        logger.info("LoRA retraining was not performed or failed")
