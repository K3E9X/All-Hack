# All-Hack - Guide Complet d'Utilisation

## TL;DR - Commandes Rapides

```bash
# 1. Installer Ollama (1 minute)
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2

# 2. Demarrer Ollama
ollama serve &

# 3. Demarrer All-Hack
cd backend && source venv/bin/activate
uvicorn app.main:app --reload --port 8001

# 4. Lancer un scan complet + exploitation auto
curl -X POST "http://localhost:8001/api/v1/exploit/auto?target_url=http://target.com/page?id=1&extract_data=true"
```

---

## Table des Matieres

1. [Installation Ollama](#1-installation-ollama)
2. [Demarrage All-Hack](#2-demarrage-all-hack)
3. [Endpoints API](#3-endpoints-api)
4. [Workflow Pentest Complet](#4-workflow-pentest-complet)
5. [Exemples Pratiques](#5-exemples-pratiques)

---

## 1. Installation Ollama

### Linux/WSL
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3.2
```

### macOS
```bash
brew install ollama
ollama pull llama3.2
```

### Windows
Telecharger: https://ollama.ai/download/windows

### Verifier l'installation
```bash
# Demarrer le serveur
ollama serve

# Dans un autre terminal, tester
curl http://localhost:11434/api/tags
```

### Modeles recommandes

| Modele | RAM | Usage |
|--------|-----|-------|
| `llama3.2` | 8GB | **Defaut - equilibre** |
| `mistral` | 6GB | Rapide |
| `codellama` | 6GB | Analyse code |
| `phi3` | 4GB | Ressources limitees |

---

## 2. Demarrage All-Hack

### Backend
```bash
cd backend
source venv/bin/activate
pip install -r requirements.txt  # premiere fois seulement
uvicorn app.main:app --reload --port 8001
```

### Frontend (optionnel)
```bash
cd frontend
npm install  # premiere fois seulement
npm run dev
```

### Verifier que tout fonctionne
```bash
# Health check
curl http://localhost:8001/health

# Statut AI
curl http://localhost:8001/api/v1/ai/status
```

---

## 3. Endpoints API

### Scans de Base

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/api/v1/scans` | POST | Demarrer un scan |
| `/api/v1/scans/{id}` | GET | Resultats du scan |
| `/api/v1/scans/{id}/status` | GET | Statut du scan |
| `/api/v1/scans/{id}/vulnerabilities` | GET | Liste des vulns |

### Exploitation Autonome (ONE-CLICK)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/api/v1/exploit/auto` | POST | **Exploitation automatique** |
| `/api/v1/exploit/session/{id}` | GET | Details d'une session |
| `/api/v1/exploit/sessions` | GET | Toutes les sessions |

### Analyse AI

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/api/v1/ai/status` | GET | Statut Ollama |
| `/api/v1/scans/{id}/analyze` | POST | Analyser toutes les vulns |
| `/api/v1/vulnerabilities/{id}/analyze` | GET | Analyser une vuln |
| `/api/v1/vulnerabilities/{id}/exploit-guide` | POST | Guide d'exploitation |
| `/api/v1/vulnerabilities/{id}/generate-fix` | POST | Generer un fix |
| `/api/v1/scans/{id}/attack-chains` | GET | Chaines d'attaque |

### Validation PoC

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/api/v1/scans/{id}/validate` | POST | Valider toutes les vulns |
| `/api/v1/vulnerabilities/{id}/validate` | POST | Valider une vuln |
| `/api/v1/scans/{id}/confirmed` | GET | Vulns confirmees |

### Chat Interactif

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/ws/chat/{scan_id}` | WebSocket | Chat temps reel |
| `/api/v1/chat/{id}/message` | POST | Envoyer un message |
| `/api/v1/chat/{id}/history` | GET | Historique du chat |

### Multi-Agent (Phase 2)

| Endpoint | Methode | Description |
|----------|---------|-------------|
| `/api/v1/agents/scan` | POST | Scan multi-agent |
| `/api/v1/agents/status` | GET | Statut des agents |
| `/api/v1/memory/stats` | GET | Stats memoire |

---

## 4. Workflow Pentest Complet

### Option A: One-Click (Recommande)

```bash
# Exploitation automatique avec extraction de donnees
curl -X POST "http://localhost:8001/api/v1/exploit/auto?\
target_url=http://target.com/page.php?id=1&\
extract_data=true&\
max_rows=100"
```

Cela fait automatiquement:
- Detection SQLi, LFI, XSS, SSRF, RCE
- Exploitation des vulns trouvees
- Extraction de donnees (tables, colonnes, donnees)
- Generation de PoC
- Raisonnement AI sur les prochaines etapes

### Option B: Workflow Manuel

```bash
# 1. Demarrer scan
SCAN_ID=$(curl -s -X POST http://localhost:8001/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://target.com", "mode": "black_box"}' \
  | jq -r '.scan_id')

# 2. Attendre completion
while true; do
  STATUS=$(curl -s http://localhost:8001/api/v1/scans/$SCAN_ID/status | jq -r '.status')
  echo "Status: $STATUS"
  [ "$STATUS" = "completed" ] && break
  sleep 5
done

# 3. Voir resultats
curl http://localhost:8001/api/v1/scans/$SCAN_ID | jq

# 4. Analyse AI
curl -X POST http://localhost:8001/api/v1/scans/$SCAN_ID/analyze | jq

# 5. Valider avec PoC
curl -X POST http://localhost:8001/api/v1/scans/$SCAN_ID/validate | jq

# 6. Identifier chaines d'attaque
curl http://localhost:8001/api/v1/scans/$SCAN_ID/attack-chains | jq
```

---

## 5. Exemples Pratiques

### SQL Injection - Exploitation Complete

```bash
# Cible avec parametre vulnerable
curl -X POST "http://localhost:8001/api/v1/exploit/auto?\
target_url=http://testphp.vulnweb.com/listproducts.php?cat=1&\
extract_data=true"
```

Reponse:
```json
{
  "session_id": "exp_abc123",
  "status": "completed",
  "vulnerabilities_found": 1,
  "extractions": 1,
  "reasoning_chain": [
    {"step": "detect", "result": "SQLi Union found in 'cat' parameter"},
    {"step": "exploit", "result": "Extracted 5 tables"},
    {"step": "extract", "result": "Got 100 rows from users table"}
  ],
  "details": {
    "extractions": [{
      "exploit_type": "sqli_union",
      "data_extracted": {
        "tables": ["users", "products", "orders"],
        "columns": {"users": ["id", "username", "password"]},
        "sample_data": [...]
      },
      "proof_of_concept": "# SQL Injection PoC\n..."
    }]
  }
}
```

### LFI - Extraction de Fichiers

```bash
curl -X POST "http://localhost:8001/api/v1/exploit/auto?\
target_url=http://target.com/page.php?file=intro.txt&\
extract_data=true"
```

Fichiers extraits automatiquement:
- `/etc/passwd`
- `/etc/shadow` (si permissions)
- `.env`
- `wp-config.php`
- Logs Apache/Nginx

### Chat avec l'AI sur les Resultats

```bash
# Creer session de chat
curl -X POST http://localhost:8001/api/v1/chat/$SCAN_ID/session

# Poser une question
curl -X POST "http://localhost:8001/api/v1/chat/$SCAN_ID/message?\
message=Comment+exploiter+la+SQLi+trouvee"
```

### Generer un Fix

```bash
curl -X POST "http://localhost:8001/api/v1/vulnerabilities/$VULN_ID/generate-fix?\
scan_id=$SCAN_ID"
```

Reponse avec code corrige pour le framework detecte (Django, Laravel, Express, etc.)

---

## Troubleshooting

### "Ollama not available"
```bash
# Verifier que Ollama tourne
ps aux | grep ollama

# Demarrer si necessaire
ollama serve
```

### "Model not found"
```bash
ollama pull llama3.2
```

### Scan lent
```bash
# Utiliser un modele plus leger
ollama pull mistral
export OLLAMA_MODEL=mistral
```

### Erreur CORS
Verifier les ports:
- Backend: 8001
- Frontend: 5173

---

## Documentation API Complete

Swagger UI disponible a: http://localhost:8001/docs

---

## Rappel Legal

- Toujours avoir une autorisation ecrite
- Tester uniquement sur vos propres applications ou avec permission
- Ce tool est pour le pentest professionnel autorise
