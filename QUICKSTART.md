# 🚀 Guide de Démarrage Rapide

## Installation Rapide (5 minutes)

### Étape 1: Installation des Dépendances

```bash
# Backend
cd backend
python3 -m venv venv
source venv/bin/activate  # Sur Windows: venv\Scripts\activate
pip install -r requirements.txt

# Frontend
cd ../frontend
npm install
```

### Étape 2: Démarrage

**Terminal 1 - Backend:**
```bash
./start-backend.sh
# Ou manuellement:
# cd backend && source venv/bin/activate && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
./start-frontend.sh
# Ou manuellement:
# cd frontend && npm run dev
```

### Étape 3: Premier Scan

1. Ouvrez votre navigateur sur http://localhost:5173
2. Entrez une URL de test (VOTRE application)
3. Choisissez "Black Box" pour commencer
4. Cliquez sur "Start Scan"

## 🎯 Exemple de Scan

### Black Box (Sans authentification)

```
URL: https://your-test-app.com
Mode: Black Box
Options: Par défaut
```

**Tests effectués:**
- ✓ Détection de technologies
- ✓ Découverte d'endpoints
- ✓ SQL Injection
- ✓ XSS
- ✓ Command Injection
- ✓ SSRF
- ✓ Headers de sécurité
- ✓ CORS misconfiguration

### Grey Box (Avec authentification)

```
URL: https://your-test-app.com
Mode: Grey Box
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Tests supplémentaires:**
- ✓ IDOR
- ✓ Escalade de privilèges
- ✓ Cloisonnement horizontal
- ✓ Tests d'accès aux fonctions admin

## 🔧 Configuration Avancée

### Backend Configuration

Créez `backend/.env`:
```env
REQUEST_TIMEOUT=30
MAX_RETRIES=3
SCAN_TIMEOUT=3600
```

### Frontend Configuration

Modifiez `frontend/src/components/Scanner.jsx`:
```javascript
// Ligne 4
const API_URL = 'http://localhost:8000/api/v1'
```

## 📊 Comprendre les Résultats

### Sévérités

| Sévérité | Couleur | Signification | Action |
|----------|---------|---------------|--------|
| CRITICAL | 🔴 Rouge | Exploitable immédiatement | Corriger ASAP |
| HIGH | 🟠 Orange | Risque élevé | Corriger rapidement |
| MEDIUM | 🟡 Jaune | Risque modéré | Corriger prochainement |
| LOW | 🔵 Bleu | Risque faible | Amélioration |
| INFO | ⚪ Gris | Information | Optionnel |

### Types de Vulnérabilités

**Injection:**
- SQL Injection → Accès base de données
- XSS → Vol de sessions
- Command Injection → Exécution de code

**Access Control:**
- IDOR → Accès données autres users
- Privilege Escalation → Devenir admin
- Broken Access → Accès non autorisé

**Misconfiguration:**
- CORS → Attaque cross-origin
- Headers → Attaques diverses
- SSL/TLS → Man-in-the-middle

## 🛠️ Troubleshooting

### "Cannot connect to backend"

```bash
# Vérifier que le backend tourne
curl http://localhost:8000/health

# Si non, redémarrer:
cd backend
source venv/bin/activate
uvicorn app.main:app --reload
```

### "CORS error"

Vérifiez que le frontend et le backend sont sur les bons ports:
- Backend: http://localhost:8000
- Frontend: http://localhost:5173

### "Scan prend trop de temps"

Options de scan dans le code `scanner_orchestrator.py`:
```python
# Ligne ~80-85 - Limiter les endpoints testés
endpoint_urls[:50]  # Au lieu de tester tous les endpoints
```

## 💡 Conseils d'Utilisation

### 1. Tests Progressifs

Commencez par:
1. Black Box sur une petite application
2. Vérifiez les résultats
3. Passez à Grey Box avec token
4. Testez sur application plus grande

### 2. Interpréter les Faux Positifs

Certains résultats peuvent être des faux positifs:
- Vérifiez manuellement les vulnérabilités CRITICAL
- Testez les payloads dans un environnement contrôlé
- Confirmez avant de rapporter

### 3. Optimiser les Performances

```javascript
// Dans Scanner.jsx, réduire les options si lent:
enable_active_tests: true,  // false pour scan rapide
enable_fuzzing: true,       // false pour scan basique
rate_limit: 10,             // augmenter pour scan plus rapide
max_depth: 3                // réduire à 1 ou 2 pour scan rapide
```

## 📚 Ressources

- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **API Documentation:** http://localhost:8000/docs (quand backend actif)
- **Bug Reports:** GitHub Issues

## ⚠️ Important

- ✅ Toujours obtenir une autorisation écrite
- ✅ Tester sur vos propres applications
- ✅ Utiliser en environnement de développement/staging
- ❌ Ne JAMAIS tester sans autorisation
- ❌ Ne JAMAIS utiliser en production sans prévenir

## 🎓 Prochaines Étapes

1. Familiarisez-vous avec l'outil
2. Testez sur une application simple
3. Comprenez chaque type de vulnérabilité
4. Apprenez à corriger les problèmes trouvés
5. Contribuez au projet !

---

**Besoin d'aide ?** Consultez le README.md complet ou ouvrez une issue sur GitHub.
