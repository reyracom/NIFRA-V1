import aiohttp
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import logging
from datetime import datetime
import json
import hashlib
from collections import Counter

logging.basicConfig(level=logging.INFO)

CDN_PATTERNS = ["cloudflare", "akamai", "fastly", "sucuri"]
STATIC_EXTENSIONS = [".png", ".jpg", ".jpeg", ".svg", ".gif", ".woff", ".woff2", ".css", ".js"]

FAVICON_DB = {
    "d41d8cd98f00b204e9800998ecf8427e": "Empty Favicon",
    "9a3e4f...": "WordPress",
    "f4c3d1...": "Laravel Nova"
}

async def fetch(session, url):
    try:
        start = datetime.utcnow()
        async with session.get(url, timeout=10, allow_redirects=True) as res:
            text = await res.text(errors="ignore")
            headers = dict(res.headers)
            content = await res.read()
            elapsed = (datetime.utcnow() - start).total_seconds()
            return url, res.status, text, headers, str(res.url), res.history, content, elapsed
    except Exception as e:
        logging.warning(f"[SurfaceDiscovery] Failed to fetch {url}: {e}")
        return url, 0, "", {}, url, [], b"", 0.0

async def discover_surface(base_url, max_depth=2, endpoint_filter=None, export_path=None):
    discovered = {
        "discovered_at": datetime.utcnow().isoformat() + "Z",
        "target": base_url,
        "depth_used": 0,
        "pages": [],
        "summary": {}
    }
    visited = set()
    queue = [base_url]
    depth = 0
    endpoint_counter = Counter()
    field_counter = Counter()

    async with aiohttp.ClientSession(headers={"User-Agent": "Mozilla/5.0"}) as session:
        while queue and depth < max_depth:
            next_queue = []
            tasks = [fetch(session, url) for url in queue if url not in visited]
            results = await asyncio.gather(*tasks)

            for url, status, html, headers, final_url, history, content, elapsed in results:
                if not html or url in visited:
                    continue
                visited.add(url)

                parsed = urlparse(final_url)
                if any(parsed.path.endswith(ext) for ext in STATIC_EXTENSIONS):
                    continue

                score = 0
                score_reason = []

                page_data = {
                    "url": url,
                    "final_url": final_url,
                    "status": status,
                    "server": headers.get("server"),
                    "x_powered_by": headers.get("x-powered-by"),
                    "x_generator": headers.get("x-generator"),
                    "response_time": elapsed,
                    "redirect_chain": [str(r.url) for r in history] if history else [],
                    "favicon_hash": None,
                    "favicon_match": None,
                    "title": None,
                    "cdn_tag": None,
                    "regex_flag": False,
                    "auth_required": False,
                    "risk_score": 0,
                    "score_reason": [],
                    "suggest_next_action": "observe",
                    "fields": [],
                    "endpoints": []
                }

                soup = BeautifulSoup(html, "html.parser")
                title_tag = soup.find("title")
                if title_tag:
                    page_data["title"] = title_tag.text.strip()

                if any(cdn in final_url.lower() for cdn in CDN_PATTERNS):
                    page_data["cdn_tag"] = "CDN/Edge Protected"

                favicon_tag = soup.find("link", rel=re.compile("icon", re.I))
                if favicon_tag and favicon_tag.get("href"):
                    favicon_url = urljoin(url, favicon_tag.get("href"))
                    try:
                        async with session.get(favicon_url, timeout=5) as fav_res:
                            if fav_res.status == 200:
                                fav_bytes = await fav_res.read()
                                fav_hash = hashlib.md5(fav_bytes).hexdigest()
                                page_data["favicon_hash"] = fav_hash
                                page_data["favicon_match"] = FAVICON_DB.get(fav_hash)
                    except:
                        pass

                if re.search(r"flag\{[a-z0-9_-]+\}", html, re.I):
                    page_data["regex_flag"] = True
                    score += 5
                    score_reason.append("Sensitive keyword: flag{...}")

                if status == 403 or "/login" in final_url or any(h for h in headers if "auth" in h.lower()):
                    page_data["auth_required"] = True
                    score += 2
                    score_reason.append("Access requires authentication")
                    page_data["suggest_next_action"] = "test auth bypass"

                forms = soup.find_all("form")
                for form in forms:
                    form_data = {
                        "method": form.get("method", "GET").upper(),
                        "inputs": {}
                    }
                    for input_tag in form.find_all("input"):
                        name = input_tag.get("name")
                        input_type = input_tag.get("type", "text")
                        if name:
                            form_data["inputs"][name] = input_type
                            if input_type in ["password", "file", "email"]:
                                score += 1
                                score_reason.append(f"Input field type: {input_type}")
                            field_counter[input_type] += 1
                    if form_data["inputs"]:
                        page_data["fields"].append(form_data)

                links = soup.find_all(["a", "script", "link", "iframe"])
                for tag in links:
                    attr = tag.get("href") or tag.get("src")
                    if attr:
                        full_url = urljoin(url, attr)
                        parsed_link = urlparse(full_url)
                        path = parsed_link.path
                        if base_url in full_url and (not endpoint_filter or re.search(endpoint_filter, path)):
                            if full_url not in visited:
                                next_queue.append(full_url)
                            page_data["endpoints"].append(path)
                            endpoint_counter[path] += 1

                if not page_data["suggest_next_action"] and score >= 3:
                    page_data["suggest_next_action"] = "inject XSS"

                page_data["risk_score"] = score
                page_data["score_reason"] = score_reason

                discovered["pages"].append(page_data)

            queue = next_queue
            depth += 1

    discovered["depth_used"] = depth
    discovered["summary"] = {
        "top_endpoints": endpoint_counter.most_common(5),
        "top_fields": field_counter.most_common(5)
    }

    if export_path:
        with open(export_path, "w") as f:
            for page in discovered["pages"]:
                entry = {
                    "discovered_at": discovered["discovered_at"],
                    "target": base_url,
                    "depth": discovered["depth_used"],
                    **page
                }
                f.write(json.dumps(entry) + "\n")

        with open(export_path.replace(".jsonl", "_summary.json"), "w") as f:
            json.dump(discovered["summary"], f, indent=2)

    return discovered

# Batching multiple domains for comparison
async def scan_batch(domains, depth=2):
    results = []
    for domain in domains:
        print(f"[Batch] Scanning {domain}...")
        result = await discover_surface(domain, max_depth=depth, export_path=f"output/{urlparse(domain).netloc}.jsonl")
        results.append(result)
    return results
