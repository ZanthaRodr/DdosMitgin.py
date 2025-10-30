#  Simulação Didática de Defesa contra DDoS
### `simula_ddos_defesa.py`

##  Descrição

Este projeto é uma **simulação didática** de um sistema de defesa contra ataques **DDoS (Distributed Denial of Service)**, desenvolvida em **Python 3**.  
O objetivo é **demonstrar técnicas defensivas** sem gerar tráfego real — todo o comportamento é **local, seguro e educativo**.

A simulação cria:
- Clientes legítimos que fazem requisições em taxas normais;
- Atacantes que simulam sobrecarga com altas taxas de requisições;
- Mecanismos defensivos que monitoram, limitam, bloqueiam e analisam comportamentos suspeitos.

>  Nenhuma porta é aberta, e **nenhum pacote real é enviado** — é puramente uma simulação para estudos de *cyber defense*.

---

##  Funcionalidades principais

###  Mecanismos de Defesa Simulados
- **Token Bucket:** Limita a taxa de requisições por IP (rate limiting).  
- **Sliding Window:** Detecta padrões de burst de tráfego em janelas temporais.  
- **Blacklist Temporária e Permanente:** Bloqueia IPs reincidentes.  
- **Desafio (Challenge):** Testa se um IP é legítimo (com chance de sucesso configurável).  
- **Honeypot:** Redireciona tráfego suspeito para observação controlada.  
- **Global Rate Alert:** Monitora a taxa total de requisições e aplica mitigação global quando o limite é excedido.  

---

##  Parâmetros configuráveis (`CONFIG`)
| Parâmetro | Descrição | Valor padrão |
|------------|------------|---------------|
| SIM_DURATION | Duração da simulação (segundos) | 30 |
| NUM_LEGITIMATE | Quantidade de IPs legítimos | 30 |
| NUM_ATTACKERS | Quantidade de IPs atacantes | 6 |
| LEGIT_RATE | Intervalo (s) entre requisições legítimas | (0.2, 1.5) |
| ATTACK_RATE | Intervalo (s) entre requisições de ataque | (0.01, 0.08) |
| TOKEN_BUCKET_RATE | Tokens adicionados por segundo | 5.0 |
| TOKEN_BUCKET_CAP | Capacidade máxima de tokens | 10.0 |
| SLIDING_WINDOW_SEC | Tamanho da janela de observação | 10 |
| SLIDING_WINDOW_THRESHOLD | Limite de requisições por janela | 30 |
| GLOBAL_RATE_THRESHOLD | Limite global de requisições/s | 200 |
| BLACKLIST_TEMP_SEC | Tempo de bloqueio temporário | 20 |
| BLACKLIST_PERM_THRESHOLD | Reincidências até banimento permanente | 3 |
| CHALLENGE_PASS_RATE | Chance de passar pelo desafio | 0.4 |
| HONEYPOT_SAMPLE_RATE | Chance de redirecionar ao honeypot | 0.3 |
| VERBOSE | Exibir logs detalhados | True |

---

##  Como executar

### 1️ Requisitos
- Python 3.8+  
- Nenhum pacote externo é necessário (apenas bibliotecas padrão)

### 2️ Execução
```bash
python simula_ddos_defesa.py
```

Durante a simulação, o sistema exibirá logs de eventos como:
```
[12:14:32] [ACCEPT] 10.1.1.3 request processed.
[12:14:33] [SUSPICION] 192.168.100.2 made 35 reqs in sliding window -> challenge (passed=False)
[12:14:33] [HONEYPOT] Redirecting 192.168.100.2 to honeypot for deep analysis.
```

Após o término, um sumário será apresentado:
```
=== SUMÁRIO DA SIMULAÇÃO ===
total_requests           : 894
accepted                 : 550
blocked_rate_limit       : 220
blocked_blacklist        : 50
challenges               : 40
challenge_passed         : 15
honeypot_hits            : 5
Permamente banned IPs    : ['192.168.100.3', '192.168.100.5']
Honeypot observed IPs    : ['192.168.100.2']
========================================
```

---

##  Estrutura do Projeto
```
simula_ddos_defesa.py      # Código principal
README.md                  # Documentação
```

---

##  Conceitos Demonstrados
- Modelagem de **ataques distribuídos** de negação de serviço.  
- Implementação de **mecanismos defensivos inteligentes** (rate limiting, blacklists dinâmicas).  
- Introdução a **estratégias de mitigação e detecção de intrusão**.  
- Simulação **assíncrona** de tráfego com asyncio.  

---

##  Sugestões de Expansão
- Exportar métricas para CSV ou gráficos (matplotlib).  
- Implementar dashboard web com Flask ou FastAPI.  
- Adicionar logs estruturados em JSON para integração com ELK/Splunk.  
- Simular clusters de servidores e balanceamento de carga.  

---

##  Licença
Distribuído sob a licença **MIT**.  
Sinta-se livre para estudar, modificar e compartilhar para fins educacionais.

---

##  Autor
**Rodrigo Zanata**  
Estudante de **Cyber Security**  
 São Manuel-SP
 [zanatha31@gmail.com] [acade31@proton.me]

