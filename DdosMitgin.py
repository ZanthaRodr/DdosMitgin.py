#!/usr/bin/env python3
#Modelo de simulação didática de defesa contra ataques DDoS
"""
Simulação Didática de Defesa contra DDoS
Arquivo: simula_ddos_defesa.py

- Simula tráfego de clientes legítimos e atacantes.
- Implementa mecanismos defensivos (token bucket, sliding window, blacklist, challenge).
- Não abre portas nem cria tráfego real — ambiente seguro e local.

Executar:
    python simula_ddos_defesa.py
"""

import asyncio
import random
import time
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Deque, Dict, Tuple, Optional

# -----------------------
# Configurações (ajustáveis)
# -----------------------
CONFIG = {
    "SIM_DURATION": 30,              # segundos da simulação
    "NUM_LEGITIMATE": 30,            # quantidade de IPs legítimos
    "NUM_ATTACKERS": 6,              # quantidade de IPs atacantes
    "LEGIT_RATE": (0.2, 1.5),        # intervalo entre requisições legit (segundos)
    "ATTACK_RATE": (0.01, 0.08),     # intervalo entre requisições atacante (segundos)
    "TOKEN_BUCKET_RATE": 5.0,        # tokens adicionados por segundo por IP (permite ~5 rps)
    "TOKEN_BUCKET_CAP": 10.0,        # capacidade máxima do bucket
    "SLIDING_WINDOW_SEC": 10,        # janela para contar requisições por IP
    "SLIDING_WINDOW_THRESHOLD": 30,  # requisições em window que sinalizam ataque
    "GLOBAL_RATE_THRESHOLD": 200,    # requisições por segundo no servidor para alerta
    "BLACKLIST_TEMP_SEC": 20,        # tempo temporário de ban (segundos)
    "BLACKLIST_PERM_THRESHOLD": 3,   # quantas vezes re-ban para tornar perm ban
    "CHALLENGE_PASS_RATE": 0.4,      # probabilidade de passar desafio (simulado)
    "HONEYPOT_SAMPLE_RATE": 0.3,     # porcentagem de suspeitos enviados ao honeypot
    "VERBOSE": True
}

# -----------------------
# Utilitários e Tipos
# -----------------------
def now() -> float:
    return time.time()

def log(msg: str):
    if CONFIG["VERBOSE"]:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}")

@dataclass
class TokenBucket:
    capacity: float
    tokens: float
    rate: float
    last_time: float = field(default_factory=now)

    def consume(self, amount: float = 1.0) -> bool:
        """Tenta consumir tokens; retorna True se permitido."""
        t = now()
        elapsed = t - self.last_time
        if elapsed > 0:
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_time = t
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

@dataclass
class SlidingWindow:
    window_size: float
    events: Deque[float] = field(default_factory=deque)

    def add_event(self):
        self.events.append(now())
        self._trim()

    def _trim(self):
        cutoff = now() - self.window_size
        while self.events and self.events[0] < cutoff:
            self.events.popleft()

    def count(self) -> int:
        self._trim()
        return len(self.events)

@dataclass
class IPState:
    ip: str
    bucket: TokenBucket
    window: SlidingWindow
    blacklist_count: int = 0
    blacklisted_until: Optional[float] = None
    perm_banned: bool = False
    last_seen: float = field(default_factory=now)
    honeypot_redirects: int = 0

# -----------------------
# Simulador de tráfego
# -----------------------
class TrafficSimulator:
    def __init__(self):
        self.ip_states: Dict[str, IPState] = {}
        self.metrics = {
            "total_requests": 0,
            "accepted": 0,
            "blocked_rate_limit": 0,
            "blocked_blacklist": 0,
            "challenges": 0,
            "challenge_passed": 0,
            "honeypot_hits": 0
        }
        self.global_events: Deque[float] = deque()

    def create_ip(self, ip: str) -> IPState:
        bucket = TokenBucket(
            capacity=CONFIG["TOKEN_BUCKET_CAP"],
            tokens=CONFIG["TOKEN_BUCKET_CAP"],
            rate=CONFIG["TOKEN_BUCKET_RATE"]
        )
        window = SlidingWindow(window_size=CONFIG["SLIDING_WINDOW_SEC"])
        state = IPState(ip=ip, bucket=bucket, window=window)
        self.ip_states[ip] = state
        return state
#First you see--------
    def is_blacklisted(self, state: IPState) -> bool:
        if state.perm_banned:
            return True
        if state.blacklisted_until and now() < state.blacklisted_until:
            return True
        return False
#And after you don't--------
    def maybe_blacklist(self, state: IPState):
        state.blacklist_count += 1
        state.blacklisted_until = now() + CONFIG["BLACKLIST_TEMP_SEC"]
        log(f"[*] Temporarily blacklisted {state.ip} for {CONFIG['BLACKLIST_TEMP_SEC']}s (count={state.blacklist_count})")
        if state.blacklist_count >= CONFIG["BLACKLIST_PERM_THRESHOLD"]:
            state.perm_banned = True
            log(f"[!!] Permanently banned {state.ip} after repeated offenses.")
#“Intelligence is the ability to adapt to change.”
    def global_rate(self) -> float:
        cutoff = now() - 1
        while self.global_events and self.global_events[0] < cutoff:
            self.global_events.popleft()
        return len(self.global_events)

    async def handle_request(self, ip: str, payload: str, source_type: str):
        """Processa uma requisição simulada de 'ip' com conteúdo 'payload'."""
        self.metrics["total_requests"] += 1
        self.global_events.append(now())
        state = self.ip_states.get(ip) or self.create_ip(ip)
        state.last_seen = now()
        state.window.add_event()

        # 1) Verifique blacklist / perm ban
        if self.is_blacklisted(state):
            self.metrics["blocked_blacklist"] += 1
            log(f"[BLOCK-BLACKLIST] {ip} request blocked (perm_banned={state.perm_banned}).")
            return False

        # 2) Global rate alert
        glr = self.global_rate()
        if glr > CONFIG["GLOBAL_RATE_THRESHOLD"]:
            log(f"[ALERT] Global requests/s = {glr} (threshold {CONFIG['GLOBAL_RATE_THRESHOLD']}). Activating stricter mitigation.")
            # Estratégia: reduzir tokens temporariamente para todos
            for s in self.ip_states.values():
                s.bucket.tokens = min(s.bucket.tokens, s.bucket.capacity * 0.2)

        # 3) Sliding window detection (burst per IP)
        ip_count = state.window.count()
        if ip_count > CONFIG["SLIDING_WINDOW_THRESHOLD"]:
            # Suspeita de ataque -> challenge / blacklist
            # Envia desafio: se falhar, blacklist temporária
            self.metrics["challenges"] += 1
            passed = random.random() < CONFIG["CHALLENGE_PASS_RATE"]
            log(f"[SUSPICION] {ip} made {ip_count} reqs in sliding window -> challenge (passed={passed})")
            if not passed:
                # decide enviar para honeypot com alguma chance
                if random.random() < CONFIG["HONEYPOT_SAMPLE_RATE"]:
                    state.honeypot_redirects += 1
                    self.metrics["honeypot_hits"] += 1
                    log(f"[HONEYPOT] Redirecting {ip} to honeypot for deep analysis.")
                    # treat as observed but not accepted
                    return False
                self.maybe_blacklist(state)
                return False
            else:
                self.metrics["challenge_passed"] += 1

        # 4) Token bucket (rate limiting)
        allowed = state.bucket.consume(1.0)
        if not allowed:
            self.metrics["blocked_rate_limit"] += 1
            log(f"[RATE-LIMIT] {ip} blocked by token bucket.")
            # aumento de suspeita: caso repetido, blacklist
            if state.window.count() > CONFIG["SLIDING_WINDOW_THRESHOLD"] // 2:
                self.maybe_blacklist(state)
            return False

        # 5) Aceitar requisição
        self.metrics["accepted"] += 1
        # Simule processamento leve
        # (em ambiente real, aqui seria manipulação do request)
        if source_type == "attacker":
            # detect patterns in payload (simulated signature detection)
            if "mal_sig" in payload:
                log(f"[SIG-DETECT] Known malicious signature seen from {ip}.")
                # imediatamente marcar mais severamente
                state.blacklist_count += 1
                if state.blacklist_count >= 1:
                    self.maybe_blacklist(state)
        # Successful handling
        log(f"[ACCEPT] {ip} request processed.")
        return True

# -----------------------
# Geradores de IP e tráfego
# -----------------------
def gen_ip_pool(prefix: str, count: int):
    """Gera IPs fictícios com prefixo, ex: '10.0.0.'"""
    return [f"{prefix}{i+1}" for i in range(count)]

async def simulate_client(sim: TrafficSimulator, ip: str, role: str, interval_range: Tuple[float, float]):
    """Simula cliente que manda requests indefinidamente até a simulação terminar."""
    while True:
        # construção simples do payload (legit tem 'ok', attacker pode ter 'mal_sig')
        if role == "legit":
            payload = "GET /resource - legit"
        else:
            # atacante pode variar e usar assinatura maliciosa em alguns pacotes
            payload = "POST /exploit - mal_sig" if random.random() < 0.6 else "POST /probe"
        await sim.handle_request(ip=ip, payload=payload, source_type=("attacker" if role == "attacker" else "legit"))
        # aguarda intervalo aleatório
        wait = random.uniform(*interval_range)
        await asyncio.sleep(wait)

# -----------------------
# Orquestração da simulação
# -----------------------
async def main_simulation():
    sim = TrafficSimulator()
    # criar pool de IPs
    legit_ips = gen_ip_pool("10.1.1.", CONFIG["NUM_LEGITIMATE"])
    attacker_ips = gen_ip_pool("192.168.100.", CONFIG["NUM_ATTACKERS"])

    # registra inicialmente todos no estado
    for ip in legit_ips + attacker_ips:
        sim.create_ip(ip)

    # cria tarefas de simulação
    tasks = []
    for ip in legit_ips:
        t = asyncio.create_task(simulate_client(sim, ip, "legit", CONFIG["LEGIT_RATE"]))
        tasks.append(t)
    for ip in attacker_ips:
        t = asyncio.create_task(simulate_client(sim, ip, "attacker", CONFIG["ATTACK_RATE"]))
        tasks.append(t)

    log("Iniciando simulação DDoS (apenas local, ambiente seguro)...")
    start = now()
    # roda por um período configurado
    try:
        await asyncio.sleep(CONFIG["SIM_DURATION"])
    finally:
        # cancel tasks
        for t in tasks:
            t.cancel()
        # deixa o loop processar cancels
        await asyncio.gather(*tasks, return_exceptions=True)
        end = now()
        log(f"Simulação finalizada (duração ~ {end - start:.1f}s).")
        # mostra sumário
        print("\n=== SUMÁRIO DA SIMULAÇÃO ===")
        for k, v in sim.metrics.items():
            print(f"{k:25s}: {v}")
        # listas de IPs perm ban e honeypot
        perm_bans = [ip for ip, s in sim.ip_states.items() if s.perm_banned]
        honeypots = [ip for ip, s in sim.ip_states.items() if s.honeypot_redirects > 0]
        print(f"Permamente banned IPs   : {perm_bans}")
        print(f"Honeypot observed IPs   : {honeypots}")
        print("=" * 40)

# -----------------------
# Entry point
# -----------------------
if __name__ == "__main__":
    try:
        asyncio.run(main_simulation())
    except KeyboardInterrupt:
        print("Simulação interrompida pelo usuário.")






