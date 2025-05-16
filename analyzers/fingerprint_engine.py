import aiohttp
import asyncio
import hashlib
import json
import logging
from urllib.parse import urlparse, urljoin
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO)

# TTL Cache implementation
class TTLCache:
    def __init__(self, ttl_seconds=3600):
        self.store = {}
        self.ttl = ttl_seconds

    def set(self, key, value):
        self.store[key] = (value, datetime.now())

    def get(self, key):
        val = self.store.get(key)
        if not val:
            return None
        data, timestamp = val
        if (datetime.now() - timestamp).total_seconds() > self.ttl:
            del self.store[key]
            return None
        return data

class AsyncFrameworkScanner:
    def __init__(self, favicon_db=None, threat_db=None, max_concurrent=10, ttl=3600):
        self.favicon_db = favicon_db or {}
        self.threat_db = threat_db or {}
        self.cache = TTLCache(ttl)
        self.semaphore = asyncio.Semaphore(max_concurrent)

    def _is_valid_url(self, url):
        try:
            parsed = urlparse(url)
            return parsed.scheme in ("http", "https") and parsed.netloc != ""
        except:
            return False

    async def _fetch(self, session, url):
        try:
            async with self.semaphore:
                async with session.get(url, timeout=10) as resp:
                    text = await resp.text()
                    headers = {k.lower(): v for k, v in resp.headers.items()}
                    return text, headers, resp.status, str(resp.url), resp.history
        except Exception as e:
            return "", {}, 0, url, []

    async def _get_favicon_hash(self, session, base_url):
        try:
            favicon_url = urljoin(base_url, "/favicon.ico")
            async with session.get(favicon_url, timeout=5) as resp:
                if resp.status == 200:
                    content = await resp.read()
                    hash_val = hashlib.md5(content).hexdigest()
                    name = self.favicon_db.get(hash_val)
                    threat = self.threat_db.get(hash_val)
                    return hash_val, name, threat
        except:
            return None, None, None
        return None, None, None

    def _detect_stack(self, text, headers):
        indicators = []

        def check(cond, label):
            if cond:
                indicators.append(label)

        check("/wp-content/" in text or "wp-json" in text, "WordPress")
        check("whoops" in text, "Laravel error")
        check("_next/static" in text, "Next.js asset")
        check("__VUE_DEVTOOLS_GLOBAL_HOOK__" in text and len(text) > 1000, "Vue.js")
        check("__REACT_DEVTOOLS_GLOBAL_HOOK__" in text and len(text) > 1000, "React")
        check("ng-version" in text, "Angular")
        check("laravel" in headers.get("x-powered-by", "").lower(), "Laravel header")
        check("x-runtime" in headers, "Rails runtime")
        check("x-rails-version" in headers, "Rails version")
        check("csrftoken" in headers.get("set-cookie", ""), "Django CSRF")
        return indicators

    async def scan(self, session, url):
        if not self._is_valid_url(url):
            return {"url": url, "framework": "invalid", "status": 0, "error": "Invalid URL"}

        if cached := self.cache.get(url):
            return cached

        text, headers, status, final_url, history = await self._fetch(session, url)
        favicon_hash, favicon_name, threat_tag = await self._get_favicon_hash(session, url)
        indicators = self._detect_stack(text.lower(), headers)

        if favicon_name:
            indicators.append(f"Favicon match: {favicon_name}")
        if threat_tag:
            indicators.append(f"Threat: {threat_tag}")

        framework = "unknown"
        for stack in ["wordpress", "laravel", "next", "vue", "react", "angular", "rails", "django"]:
            if any(stack in ind.lower() for ind in indicators):
                framework = stack
                break

        confidence = (
            "high" if len(indicators) >= 3 else
            "medium" if len(indicators) == 2 else
            "low" if len(indicators) == 1 else
            "none"
        )

        result = {
            "url": final_url,
            "framework": framework,
            "status": status,
            "confidence": confidence,
            "indicators": indicators,
            "favicon_hash": favicon_hash,
            "favicon_name": favicon_name,
            "threat": threat_tag,
            "redirected": len(history) > 0
        }

        self.cache.set(url, result)
        return result

    async def scan_batch(self, url_list):
        async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
            tasks = [self.scan(session, url) for url in url_list]
            return await asyncio.gather(*tasks)
