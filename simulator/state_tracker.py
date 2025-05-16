import json
import os
from datetime import datetime

STATE_FILE = "simulator/state_context.json"

class StateTracker:
    def __init__(self, path=STATE_FILE):
        self.path = path
        # Buat direktori jika belum ada
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.state = self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                # File rusak, buat baru
                pass
        return {
            "logins": {},
            "injections": [],
            "endpoints": {},
            "forms": [],
            "vulnerabilities": []
        }

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.state, f, indent=2)

    def record_login(self, domain, success):
        self.state["logins"][domain] = {
            "success": success,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.save()

    def record_injection(self, url, field, payload, result):
        entry = {
            "url": url,
            "field": field,
            "payload": payload,
            "status": result.get("status"),
            "response_time": result.get("response_time"),
            "timestamp": datetime.utcnow().isoformat()
        }

        self.state["injections"].append(entry)

        # Jika ada tanda-tanda kerentanan
        if result.get("status") == "success" or result.get("bypassed") or result.get("reflection"):
            vulnerability = {
                "url": url,
                "field": field,
                "payload_type": self._classify_payload(payload),
                "severity": self._determine_severity(result),
                "timestamp": datetime.utcnow().isoformat(),
                "status_code": result.get("http_status", 0),
                "response_time": result.get("response_time", 0)
            }
            self.state["vulnerabilities"].append(vulnerability)

        self.save()

    def _classify_payload(self, payload):
        """Klasifikasi jenis payload berdasarkan isi"""
        payload = payload.lower()

        if any(x in payload for x in ["select", "union", "from", "where", "1=1", "--", "'"]):
            return "sql_injection"
        elif any(x in payload for x in ["<script", "alert(", "onerror", "onload"]):
            return "xss"
        elif any(x in payload for x in ["../", "etc/passwd", "win.ini"]):
            return "path_traversal"
        elif any(x in payload for x in ["admin", "password", "login", "token"]):
            return "authentication"
        else:
            return "generic"

    def _determine_severity(self, result):
        """Tentukan tingkat keparahan berdasarkan hasil"""
        if result.get("bypassed") and result.get("reflection"):
            return "high"
        elif result.get("bypassed") or result.get("reflection"):
            return "medium"
        else:
            return "low"

    def record_endpoint(self, domain, path, status):
        self.state["endpoints"].setdefault(domain, {})[path] = {
            "status": status,
            "seen": True,
            "timestamp": datetime.utcnow().isoformat()
        }
        self.save()

    def record_form(self, url, field_list):
        self.state["forms"].append({
            "url": url,
            "fields": field_list,
            "timestamp": datetime.utcnow().isoformat()
        })
        self.save()

    def record_framework(self, domain, framework, confidence):
            """Record detected framework for a domain"""
            if "frameworks" not in self.state:
                self.state["frameworks"] = {}
                
            self.state["frameworks"][domain] = {
                "name": framework,
                "confidence": confidence,
                "detected_at": datetime.utcnow().isoformat()
            }
            self.save()

    def get_summary(self):
        """Dapatkan ringkasan status pengujian"""
        vulns_by_severity = {"high": 0, "medium": 0, "low": 0}
        for vuln in self.state.get("vulnerabilities", []):
            severity = vuln.get("severity", "low")
            vulns_by_severity[severity] = vulns_by_severity.get(severity, 0) + 1

        return {
            "total_injections": len(self.state["injections"]),
            "total_endpoints": sum(len(eps) for eps in self.state["endpoints"].values()),
            "total_forms": len(self.state["forms"]),
            "total_vulnerabilities": len(self.state.get("vulnerabilities", [])),
            "vulnerabilities_by_severity": vulns_by_severity,
            "last_updated": datetime.utcnow().isoformat()
        }
