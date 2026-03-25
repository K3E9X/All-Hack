# All-Hack API Reference

Base URL: `http://localhost:8001/api/v1`

---

## Exploitation Autonome

### POST `/exploit/auto`

**Exploitation automatique one-click** - Detecte et exploite les vulnerabilites automatiquement.

#### Parametres Query

| Parametre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `target_url` | string | Oui | URL cible avec parametres (ex: `http://site.com/page?id=1`) |
| `parameters` | array | Non | Parametres specifiques a tester |
| `extract_data` | bool | Non | Extraire les donnees apres detection (defaut: true) |
| `max_rows` | int | Non | Nombre max de lignes a extraire (defaut: 100, max: 1000) |

#### Exemple

```bash
curl -X POST "http://localhost:8001/api/v1/exploit/auto?\
target_url=http://example.com/search?q=test&\
extract_data=true&\
max_rows=50"
```

#### Reponse

```json
{
  "session_id": "exp_1234567890",
  "status": "completed",
  "vulnerabilities_found": 2,
  "extractions": 1,
  "reasoning_chain": [
    {"step": "init", "reasoning": "Starting analysis..."},
    {"step": "detect", "result": "Found SQLi in 'q' parameter"},
    {"step": "exploit", "result": "Union-based SQLi successful"},
    {"step": "extract", "result": "Extracted 50 rows from users"}
  ],
  "details": {
    "session_id": "exp_1234567890",
    "target_url": "http://example.com/search?q=test",
    "start_time": "2024-01-15T10:30:00",
    "status": "completed",
    "vulnerabilities_found": [...],
    "extractions": [...]
  }
}
```

### GET `/exploit/session/{session_id}`

Recuperer les details d'une session d'exploitation.

### GET `/exploit/sessions`

Lister toutes les sessions d'exploitation.

---

## Scans

### POST `/scans`

Demarrer un nouveau scan de securite.

#### Body JSON

```json
{
  "target_url": "http://example.com",
  "mode": "black_box",
  "scan_depth": "normal",
  "enable_active_tests": true,
  "enable_fuzzing": true,
  "rate_limit": 10,
  "max_depth": 3,
  "auth_token": null
}
```

| Champ | Type | Description |
|-------|------|-------------|
| `target_url` | string | URL cible |
| `mode` | string | `black_box` ou `grey_box` |
| `scan_depth` | string | `quick`, `normal`, `deep` |
| `enable_active_tests` | bool | Tests actifs (SQLi, XSS, etc.) |
| `enable_fuzzing` | bool | Fuzzing des parametres |
| `rate_limit` | int | Requetes par seconde |
| `max_depth` | int | Profondeur de crawl |
| `auth_token` | string | Token JWT pour grey_box |

### GET `/scans/{scan_id}`

Resultats complets du scan.

### GET `/scans/{scan_id}/status`

Statut du scan (running, completed, failed).

### GET `/scans/{scan_id}/vulnerabilities`

Liste des vulnerabilites trouvees.

#### Parametres Query

| Parametre | Type | Description |
|-----------|------|-------------|
| `severity` | string | Filtrer par severite (critical, high, medium, low, info) |

### GET `/scans/{scan_id}/summary`

Resume avec statistiques.

---

## Analyse AI

### GET `/ai/status`

Statut d'Ollama et des modeles disponibles.

#### Reponse

```json
{
  "available": true,
  "provider": "Ollama (local)",
  "model": "llama3.2",
  "endpoint": "http://localhost:11434",
  "cost": "$0 (free)"
}
```

### POST `/scans/{scan_id}/analyze`

Analyser toutes les vulnerabilites avec l'AI.

#### Reponse

```json
{
  "scan_id": "scan_123",
  "analyzed": 5,
  "vulnerability_analyses": [
    {
      "vulnerability_id": "vuln_1",
      "vulnerability_title": "SQL Injection",
      "analysis": {
        "root_cause": "User input concatenated in SQL query",
        "exploitation_complexity": "trivial",
        "business_impact": "Critical - full database access",
        "remediation_code": "# Use parameterized queries...",
        "next_steps": ["Patch immediately", "Audit similar code"],
        "full_analysis": "..."
      }
    }
  ],
  "strategic_summary": {
    "overall_risk": "critical",
    "priority_fixes": [...],
    "attack_surface": "high"
  }
}
```

### GET `/vulnerabilities/{vuln_id}/analyze`

Analyser une vulnerabilite specifique.

#### Parametres Query

| Parametre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `scan_id` | string | Oui | ID du scan |

### POST `/vulnerabilities/{vuln_id}/exploit-guide`

Guide d'exploitation AI.

#### Parametres Query

| Parametre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `scan_id` | string | Oui | ID du scan |
| `question` | string | Oui | Question a poser (ex: "How to exploit this?") |

### POST `/vulnerabilities/{vuln_id}/generate-fix`

Generer du code de correction.

### GET `/scans/{scan_id}/attack-chains`

Identifier les chaines d'attaque multi-etapes.

---

## Validation PoC

### POST `/scans/{scan_id}/validate`

Valider toutes les vulnerabilites avec des PoC automatiques.

#### Reponse

```json
{
  "scan_id": "scan_123",
  "validated": 3,
  "statistics": {
    "confirmed": 2,
    "likely": 1,
    "false_positive": 0
  },
  "results": [
    {
      "vulnerability": {...},
      "validation": {
        "status": "confirmed",
        "confidence": 0.95,
        "evidence": "Database version extracted: MySQL 8.0.28",
        "validator": "sqli_validator"
      }
    }
  ]
}
```

### POST `/vulnerabilities/{vuln_id}/validate`

Valider une vulnerabilite specifique.

### GET `/scans/{scan_id}/confirmed`

Obtenir uniquement les vulnerabilites confirmees.

#### Parametres Query

| Parametre | Type | Description |
|-----------|------|-------------|
| `min_confidence` | float | Confiance minimum (defaut: 0.7) |

---

## Chat Interactif

### WebSocket `/ws/chat/{scan_id}`

Chat temps reel avec streaming.

#### Messages Client -> Serveur

```json
{"message": "What are the critical vulnerabilities?"}
```

#### Messages Serveur -> Client

```json
{"type": "assistant_chunk", "content": "The critical..."}
{"type": "assistant_complete"}
```

### POST `/chat/{scan_id}/session`

Creer une session de chat.

### POST `/chat/{scan_id}/message`

Envoyer un message (non-streaming).

#### Parametres Query

| Parametre | Type | Requis | Description |
|-----------|------|--------|-------------|
| `message` | string | Oui | Message a envoyer |

### GET `/chat/{scan_id}/history`

Historique des messages.

---

## Multi-Agent System

### POST `/agents/scan`

Demarrer un scan avec le systeme multi-agent.

Agents:
- **Orchestrator**: Coordonne le workflow
- **Recon**: Reconnaissance intelligente
- **Exploitation**: Payloads adaptatifs
- **Analysis**: Correlation des vulns
- **Reporting**: Rapports executifs

### GET `/agents/status`

Statut de tous les agents.

### GET `/agents/scan/{scan_id}/workflow`

Statut du workflow multi-agent.

---

## Systeme de Memoire

### GET `/memory/stats`

Statistiques de la memoire (scans appris).

### GET `/memory/similar`

Trouver des scans similaires.

#### Parametres Query

| Parametre | Type | Description |
|-----------|------|-------------|
| `target_url` | string | URL a comparer |
| `limit` | int | Nombre de resultats |

### GET `/memory/payloads/{vuln_type}`

Payloads qui ont fonctionne dans le passe.

#### Parametres Query

| Parametre | Type | Description |
|-----------|------|-------------|
| `technology` | string | Filtrer par techno (php, nodejs, etc.) |

### POST `/memory/store/{scan_id}`

Sauvegarder un scan en memoire.

---

## Base de Vulnerabilites

### POST `/vulns/update`

Mettre a jour la base depuis NVD/GitHub.

### GET `/vulns/search`

Rechercher des CVE.

#### Parametres Query

| Parametre | Type | Description |
|-----------|------|-------------|
| `query` | string | Recherche textuelle |
| `severity` | string | Filtrer par severite |
| `tags` | string | Tags separes par virgule |
| `has_exploit` | bool | Uniquement avec exploit connu |

### GET `/vulns/{vuln_id}`

Details d'un CVE specifique.

### POST `/vulns/search-pocs`

Rechercher des PoC sur GitHub.

---

## Codes d'Erreur

| Code | Signification |
|------|---------------|
| 200 | Succes |
| 400 | Requete invalide |
| 404 | Ressource non trouvee |
| 503 | Service indisponible (Ollama down) |
| 500 | Erreur serveur |

---

## Rate Limiting

Pas de rate limiting par defaut. Configurable dans `.env`:

```env
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_PERIOD=60
```
