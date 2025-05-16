# test_nifra.py
import asyncio
import sys
import os
import importlib

# Tambahkan path saat ini ke sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

async def test_setup():
    """Pengujian sederhana untuk memverifikasi instalasi NIFRA"""
    print("[NIFRA Tester] Checking NIFRA installation...")
    
    try:
        # Perbaiki path modul sesuai struktur folder yang sebenarnya
        modules_to_check = {
            'agents.attack_agent': 'attack_agent',
            'agents.defense_agent': 'defense_agent', 
            'agents.evaluator_agent': 'evaluator_agent',
            'simulator.executor': 'executor',  # Sudah benar
            'analyzers.fingerprint_engine': 'fingerprint_engine', 
            'trainer.memory_logger': 'memory_logger',
            'agents.prompt_memory': 'prompt_memory', 
            'agents.reasoner_agent': 'reasoner_agent',
            'simulator.state_tracker': 'state_tracker',
            'trainer.strategy_updater': 'strategy_updater', 
            'utils.surface_discovery': 'surface_discovery',  # Sudah benar 
            'agents.task_generator': 'task_generator',
            'simulator.reward_engine': 'reward_engine'  # Perbaikan lokasi
        }
        
        missing_modules = []
        for module, name in modules_to_check.items():
            try:
                importlib.import_module(module)
                print(f"[NIFRA Tester] ✓ Found {name}")
            except ImportError as e:
                missing_modules.append(f"{name} ({str(e)})")
                print(f"[NIFRA Tester] ✗ Missing {name}: {str(e)}")
        
        if missing_modules:
            print(f"[NIFRA Tester] FAIL: Missing modules: {', '.join(missing_modules)}")
            return False
        
        # Uji direktori
        for directory in ['logs', 'sandbox', 'simulator', 'trainer']:
            if not os.path.exists(directory):
                print(f"[NIFRA Tester] Creating directory: {directory}")
            os.makedirs(directory, exist_ok=True)
        
        # Uji koneksi jaringan dasar
        import requests
        try:
            requests.get("https://example.com", timeout=5)
            print("[NIFRA Tester] ✓ Network connection OK")
        except:
            print("[NIFRA Tester] WARNING: Network connection issue - could not reach example.com")
        
        # Uji Ollama API jika ada
        try:
            resp = requests.get("http://localhost:11434", timeout=2)
            if resp.status_code == 200:
                print("[NIFRA Tester] ✓ Ollama API available")
            else:
                print("[NIFRA Tester] WARNING: Ollama API returned unexpected status")
        except:
            print("[NIFRA Tester] WARNING: Ollama API not available. Will use fallback evaluation.")
        
        print("[NIFRA Tester] SUCCESS: All checks passed!")
        return True
        
    except Exception as e:
        print(f"[NIFRA Tester] ERROR: {str(e)}")
        return False

if __name__ == "__main__":
    if asyncio.run(test_setup()):
        print("\n[NIFRA Tester] You can now run NIFRA with:")
        print("python3 main.py --target-url https://example.com")
        print("python3 main.py --target-url https://reyralabs.com --iterations 3")
    else:
        print("\n[NIFRA Tester] Fix the issues above before running NIFRA")
        sys.exit(1)
