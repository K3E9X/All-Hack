# Advanced Pentest Tool 🔐

Un outil automatisé de test d'intrusion pour applications web avec interface dark & minimaliste.

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.9+-green)
![React](https://img.shields.io/badge/react-18+-61dafb)
![License](https://img.shields.io/badge/license-MIT-orange)

## ⚠️ Avertissement Légal

**IMPORTANT:** Cet outil est destiné UNIQUEMENT à des fins éducatives et de tests de sécurité autorisés. Utilisez-le UNIQUEMENT sur des applications que vous possédez ou pour lesquelles vous avez une autorisation écrite explicite. Les tests d'intrusion non autorisés sont illégaux et peuvent entraîner des poursuites.

## 🚀 Fonctionnalités

### Tests de Sécurité

- **OWASP Top 10**
  - Injection SQL (Error-based, Blind, Time-based)
  - Cross-Site Scripting (XSS) - Reflected, Stored, DOM
  - Command Injection
  - SSRF (Server-Side Request Forgery)
  - XXE (XML External Entities)

- **Contrôle d'Accès**
  - IDOR (Insecure Direct Object Reference)
  - Escalade de privilèges verticale
  - Cloisonnement horizontal
  - Broken Access Control

- **Misconfigurations**
  - Headers de sécurité manquants
  - CORS misconfiguration
  - Information Disclosure
  - SSL/TLS weaknesses

- **Reconnaissance**
  - Détection des technologies (frameworks, serveurs, etc.)
  - Énumération d'endpoints (crawling + fuzzing)
  - Découverte de fichiers sensibles
  - Analyse de la surface d'attaque

### Modes de Scan

- **Black Box**: Tests externes sans authentification
- **Grey Box**: Tests avec authentification et connaissance partielle

### Interface Utilisateur

- Design dark & minimaliste
- Affichage en temps réel de la progression
- Visualisation détaillée des vulnérabilités
- Export des résultats (à venir)

## 📋 Prérequis

- Python 3.9 ou supérieur
- Node.js 16+ et npm
- Git

## 🛠️ Installation

### 1. Cloner le repository

```bash
git clone <your-repo-url>
cd devasc-study-team
```

### 2. Installation du Backend

```bash
cd backend

# Créer un environnement virtuel
python -m venv venv

# Activer l'environnement virtuel
# Sur Linux/Mac:
source venv/bin/activate
# Sur Windows:
venv\Scripts\activate

# Installer les dépendances
pip install -r requirements.txt
```

### 3. Installation du Frontend

```bash
cd frontend
npm install
```

## 🎯 Utilisation

### Démarrer le Backend

```bash
cd backend
source venv/bin/activate  # ou venv\Scripts\activate sur Windows
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Le backend sera accessible sur `http://localhost:8000`

### Démarrer le Frontend

```bash
cd frontend
npm run dev
```

Le frontend sera accessible sur `http://localhost:5173`

### Lancer un Scan

1. Ouvrez votre navigateur sur `http://localhost:5173`
2. Entrez l'URL cible (votre application)
3. Choisissez le mode de scan:
   - **Black Box**: Sans authentification
   - **Grey Box**: Avec token d'authentification (optionnel)
4. Cliquez sur "Start Scan"
5. Attendez les résultats (temps variable selon la taille de l'application)

## 🔧 Configuration

### Variables d'Environnement (Backend)

Créez un fichier `.env` dans le dossier `backend/` :

```env
# API Configuration
API_TITLE=Advanced Pentest Tool
API_VERSION=1.0.0
API_PREFIX=/api/v1

# CORS
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173

# Scanning Configuration
MAX_CONCURRENT_SCANS=5
SCAN_TIMEOUT=3600
REQUEST_TIMEOUT=30
MAX_RETRIES=3
```

### Configuration Frontend

Modifiez `frontend/src/components/Scanner.jsx` pour changer l'URL de l'API si nécessaire:

```javascript
const API_URL = 'http://localhost:8000/api/v1'
```

## 📊 Architecture

```
devasc-study-team/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI application
│   │   ├── config.py            # Configuration
│   │   ├── models/              # Modèles de données
│   │   ├── scanners/            # Modules de scan
│   │   │   ├── reconnaissance/  # Détection tech & endpoints
│   │   │   ├── owasp/          # OWASP Top 10 scanners
│   │   │   ├── access_control/ # Tests de contrôle d'accès
│   │   │   └── misconfig/      # Tests de misconfiguration
│   │   ├── utils/              # Utilitaires
│   │   └── scanner_orchestrator.py  # Orchestrateur principal
│   └── requirements.txt
│
└── frontend/
    ├── src/
    │   ├── components/
    │   │   ├── Scanner.jsx     # Interface de scan
    │   │   └── Results.jsx     # Affichage des résultats
    │   ├── App.jsx
    │   └── index.css
    └── package.json
```

## 🔍 Types de Vulnérabilités Détectées

### CRITICAL (Critique)
- SQL Injection
- Command Injection
- SSRF avec accès aux métadonnées cloud
- Escalade de privilèges verticale
- CORS avec wildcard et credentials

### HIGH (Élevé)
- XSS (Cross-Site Scripting)
- IDOR (Insecure Direct Object Reference)
- CORS misconfiguration
- Broken Access Control

### MEDIUM (Moyen)
- Headers de sécurité manquants (CSP, HSTS)
- Clickjacking (X-Frame-Options)
- Énumération de ressources

### LOW (Faible)
- Information Disclosure
- Missing Referrer-Policy
- Headers révélant des informations techniques

## 🎨 Personnalisation

### Modifier les Couleurs (Frontend)

Éditez `frontend/tailwind.config.js`:

```javascript
colors: {
  dark: {
    bg: '#0a0a0a',      // Fond principal
    card: '#141414',    // Fond des cartes
    border: '#2a2a2a',  // Bordures
    hover: '#1f1f1f',   // Hover states
  },
  accent: {
    primary: '#00ff9f',   // Couleur primaire
    secondary: '#00ccff', // Couleur secondaire
    danger: '#ff3b3b',    // Danger/Critical
    warning: '#ffaa00',   // Warning/High
  }
}
```

### Ajouter des Tests Personnalisés

1. Créez un nouveau scanner dans `backend/app/scanners/`
2. Importez-le dans `scanner_orchestrator.py`
3. Ajoutez-le à la séquence de scan dans `_execute_scan()`

## 🐛 Dépannage

### Le backend ne démarre pas

```bash
# Vérifiez que vous êtes dans le bon environnement virtuel
which python  # Devrait pointer vers venv/bin/python

# Réinstallez les dépendances
pip install -r requirements.txt --force-reinstall
```

### Le frontend affiche une erreur CORS

- Vérifiez que le backend est démarré sur le port 8000
- Vérifiez les `ALLOWED_ORIGINS` dans `backend/app/config.py`

### Les scans échouent

- Vérifiez que l'URL cible est accessible
- Vérifiez les logs du backend dans le terminal
- Assurez-vous que l'application cible n'a pas de rate limiting strict

## 🔒 Sécurité

- Ne jamais exposer cet outil sur Internet
- Utilisez-le uniquement sur des réseaux privés/locaux
- Gardez les résultats de scan confidentiels
- Ne partagez pas les tokens d'authentification

## 📝 TODO / Améliorations Futures

- [ ] Export des résultats en PDF/JSON
- [ ] Intégration de Nuclei templates
- [ ] Intégration de SQLMap
- [ ] Support de l'authentification par cookies
- [ ] Scan de vulnérabilités JavaScript (npm audit style)
- [ ] Tests de logique métier
- [ ] Webhooks pour notifications
- [ ] Multi-threading pour scans plus rapides
- [ ] Base de données pour historique des scans

## 🤝 Contribution

Les contributions sont les bienvenues ! N'hésitez pas à :

1. Fork le projet
2. Créer une branche (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrir une Pull Request

## 📜 License

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 👨‍💻 Auteur

Développé pour des besoins éducatifs et de test de sécurité autorisés.

## 🙏 Remerciements

- OWASP pour les standards de sécurité
- La communauté de la cybersécurité
- Tous les contributeurs open source

---

**Rappel:** Utilisez cet outil de manière responsable et éthique. Le hacking éthique nécessite toujours une autorisation explicite.
