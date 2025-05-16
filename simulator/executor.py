# simulator/executor.py
import requests
from urllib.parse import urljoin
import json
import logging
import random
import re
import asyncio
import time
import os
from bs4 import BeautifulSoup
import sys

# Tambahkan path ke Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Menekan warning terkait TLS/SSL
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Import surface_discovery
from utils.surface_discovery import discover_surface

logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('NIFRA-Executor')

def login_if_needed(target):
    """Melakukan login jika kredensial diberikan"""
    auth = target.get("auth")
    login_url = target.get("login_url") or urljoin(target["url"], "/login")
    session = requests.Session()
    
    # Set user agent
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (NIFRA Security Audit)"
    })

    if auth and auth.get("user") and auth.get("pass"):
        try:
            logger.info(f"Logging in to {login_url} ...")
            resp = session.post(login_url, data={
                "username": auth["user"], 
                "password": auth["pass"]
            }, timeout=10, verify=False)
            
            if resp.status_code in [200, 302]:
                logger.info("Login successful")
            else:
                logger.warning(f"Login failed with status {resp.status_code}")
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
    return session

def extract_csrf_token(html):
    """Ekstrak token CSRF dari halaman HTML"""
    try:
        soup = BeautifulSoup(html, "html.parser")
        # Cari token dengan beberapa nama umum
        token = soup.find("input", attrs={"name": re.compile("csrf|token|nonce", re.I)})
        if token:
            return token.get("value")
        
        # Cari meta tag yang mungkin berisi token (Laravel, dll)
        meta = soup.find("meta", attrs={"name": re.compile("csrf-token", re.I)})
        if meta:
            return meta.get("content")
            
        return None
    except Exception as e:
        logger.error(f"Error extracting CSRF token: {str(e)}")
        return None

def is_safe_payload(payload):
    """Memeriksa apakah payload aman untuk dieksekusi"""
    dangerous_patterns = [
        "rm -rf", "drop table", "delete from", "system(", "exec(", 
        "eval(", "; rm ", "format c:", "deltree", "rundll32",
        "document.cookie", "window.location", ";shutdown", ":(){ :|:& };:"
    ]
    return not any(pattern in payload.lower() for pattern in dangerous_patterns)

def execute_attack(payload, target_config):
    """Eksekusi pengujian keamanan terhadap target"""
    # Validasi payload untuk keamanan
    if not is_safe_payload(payload):
        logger.warning(f"Payload ditolak karena berpotensi berbahaya: {payload[:50]}...")
        return {
            "status": "BLOCKED",
            "output": "Payload rejected for safety reasons",
            "headers": {},
            "cookies": {},
            "injected_field": None,
            "url": target_config["url"],
            "response_time": 0.0,
            "bypassed": False
        }

    url = target_config["url"]
    injected_field = None
    scan_limit = target_config.get("scan_limit", 10)
    
    # Buat direktori log jika belum ada
    os.makedirs("logs", exist_ok=True)
    
    # Setup session dan login jika perlu
    session = login_if_needed(target_config)
    
    try:
        logger.info(f"Running surface discovery on {url}")
        
        # Perbaikan: gunakan pendekatan alternatif untuk surface discovery
        try:
            # Buat loop baru jika dalam event loop, atau gunakan loop yang ada
            if asyncio.get_event_loop().is_running():
                # Jika dalam event loop, gunakan pendekatan yang berbeda
                logger.info("Using alternative surface discovery approach")
                # Buat HTTP request sederhana sebagai alternatif
                resp = session.get(url, timeout=10, verify=False)
                soup = BeautifulSoup(resp.text, 'html.parser')
                forms = soup.find_all('form')
                
                surface = {
                    "pages": [{
                        "url": url,
                        "fields": [{"method": form.get("method", "POST").upper(), 
                                    "inputs": {inp.get("name"): inp.get("type", "text") 
                                            for inp in form.find_all(["input", "textarea"]) 
                                            if inp.get("name")}} 
                                for form in forms]
                    }]
                }
            else:
                # Jika tidak dalam event loop, gunakan asyncio.run() normal
                surface = asyncio.run(discover_surface(url, max_depth=2))
        except Exception as e:
            logger.error(f"Surface discovery failed: {str(e)}")
            # Fallback jika surface discovery gagal
            surface = {"pages": [{"url": url, "fields": []}]}
        
        attack_url = url
        data = {}
        method = "POST"
        count = 0
        found_form = False

        # Cari form yang dapat digunakan untuk injeksi
        for page in surface["pages"]:
            if count >= scan_limit:
                break

            # Cek form pada halaman
            for form in page.get("fields", []):
                if count >= scan_limit:
                    break

                inputs = form.get("inputs", {})
                if not inputs:
                    continue
                    
                method = form.get("method", "POST").upper()
                found_form = True

                # Coba dapatkan token CSRF jika diperlukan
                csrf_token = None
                try:
                    logger.info(f"Getting page for CSRF token: {page['url']}")
                    get_page = session.get(page["url"], timeout=5, verify=False)
                    csrf_token = extract_csrf_token(get_page.text)
                    if csrf_token:
                        logger.info(f"CSRF token found: {csrf_token[:10]}...")
                except Exception as e:
                    logger.error(f"Error getting CSRF token: {str(e)}")

                # Pilih field untuk diinjeksi (prioritaskan text, search, atau hidden)
                text_fields = [k for k, v in inputs.items() 
                              if isinstance(v, str) and v.lower() in ['text', 'search', 'hidden', '']]
                
                if text_fields:
                    injected_field = random.choice(text_fields)
                else:
                    injected_field = random.choice(list(inputs.keys())) if inputs else "username"
                
                # Siapkan data untuk form
                data = {}
                for k in inputs.keys():
                    if re.search("csrf|token|nonce", k, re.I) and csrf_token:
                        data[k] = csrf_token
                    elif k == injected_field:
                        data[k] = payload
                    elif k.lower() in ["email", "mail"]:
                        data[k] = "test@example.com"
                    elif k.lower() in ["password", "pass"]:
                        data[k] = "Test123!"
                    else:
                        data[k] = "test"

                attack_url = page["url"]
                logger.info(f"Form found. Injecting into field '{injected_field}' at URL: {attack_url}")
                break
                
            if found_form:
                count += 1
                break

        # Jika tidak ada form, gunakan parameter query
        if not data:
            logger.info("No forms found, using query parameters")
            injected_field = "q"
            data = {injected_field: payload}
            method = "GET"

        logger.info(f"Executing {method} request to {attack_url}")
        start_time = time.time()

        # Eksekusi permintaan berdasarkan metode
        try:
            if method == "POST":
                resp = session.post(attack_url, data=data, timeout=10, verify=False)
            else:
                resp = session.get(attack_url, params=data, timeout=10, verify=False)
            
            elapsed = time.time() - start_time
            
            # Analisis respons untuk tanda-tanda keberhasilan
            response_text = resp.text
            has_reflection = payload in response_text
            error_patterns = [
                'sql syntax', 'error in your sql', 'mysql error', 
                'syntax error', 'unexpected token', 'undefined index',
                'warning: ', 'fatal error', 'stack trace', 'system error'
            ]
            has_error = any(pattern in response_text.lower() for pattern in error_patterns)
            
            # Tentukan status berdasarkan analisis
            status = "success" if (has_reflection or has_error) else "failed"
            if resp.status_code >= 400:
                status = "blocked" if resp.status_code in [403, 429] else "error"
            
            logger.info(f"Request completed: Status={resp.status_code}, Time={elapsed:.2f}s, Result={status}")
            
            return {
                "status": status,
                "http_status": resp.status_code,
                "headers": dict(resp.headers),
                "cookies": requests.utils.dict_from_cookiejar(resp.cookies),
                "output": resp.text[:1000],
                "injected_field": injected_field,
                "url": attack_url,
                "response_time": elapsed,
                "reflection": has_reflection,
                "bypassed": has_error,
                "method": method
            }
        except Exception as e:
            logger.error(f"Request execution error: {str(e)}")
            return {
                "status": "error",
                "output": f"Request failed: {str(e)}",
                "headers": {},
                "cookies": {},
                "injected_field": injected_field,
                "url": attack_url,
                "response_time": 0.0,
                "method": method
            }
            
    except Exception as e:
        logger.error(f"Execution failed: {str(e)}")
        return {
            "status": "error",
            "output": f"Execution failed: {str(e)}",
            "headers": {},
            "cookies": {},
            "injected_field": None,
            "url": url,
            "response_time": 0.0
        }
