# ComplianceOS — Guide de déploiement

## PARTIE 1 — LOCAL (Windows, sans Docker)

### Prérequis
- Python 3.11+ ✅ (vous avez 3.14)
- Git ✅
- Compte Supabase gratuit (remplace PostgreSQL local) → https://supabase.com

---

### Étape 1 — Base de données Supabase (5 min)

1. Créer un compte sur https://supabase.com → New project
2. Notez votre `DATABASE_URL` :
   Format : `postgresql://postgres:[PASSWORD]@db.[REF].supabase.co:5432/postgres`
3. Dans Supabase → SQL Editor → coller et exécuter `db/init.sql`

---

### Étape 2 — API Keys (gratuites)

| Service | URL | Temps |
|---------|-----|-------|
| Companies House | https://developer.company-information.service.gov.uk/get-started | 2 min |
| NameScan (free tier) | https://namescan.io/FreeTrialRegistration | 2 min |
| JWT Secret | `python -c "import secrets; print(secrets.token_hex(32))"` | 10 sec |

---

### Étape 3 — Configurer .env

```bash
cp .env.example .env
# Remplir DATABASE_URL, JWT_SECRET, CH_API_KEY, NAMESCAN_API_KEY
```

---

### Étape 4 — Lancer l'API

```powershell
# Dans le dossier complianceos/
.\venv\Scripts\activate
cd api
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

→ API : http://localhost:8000
→ Swagger docs : http://localhost:8000/docs
→ Dashboard HTML : ouvrir frontend/dashboard.html dans Chrome

---

## PARTIE 2 — PRODUCTION INTERNET

### Option A — Railway (recommandé, le plus simple)

Railway = hébergeur qui lit votre code et déploie automatiquement.
Coût : ~$5/mois pour un projet (DB incluse)

**1. Créer un repo GitHub**
```bash
cd complianceos
git init
git add .
git commit -m "Initial commit — ComplianceOS"
# Sur github.com → New repository → complianceos
git remote add origin https://github.com/VOTRE_USERNAME/complianceos.git
git push -u origin main
```

**2. Déployer sur Railway**
1. Aller sur https://railway.app → New Project
2. "Deploy from GitHub repo" → sélectionner `complianceos`
3. Railway détecte le Dockerfile automatiquement ✓
4. Ajouter un service PostgreSQL : "+ New" → PostgreSQL
5. Dans Variables, ajouter :
   ```
   DATABASE_URL     = (auto-rempli par Railway)
   JWT_SECRET       = votre-secret-32-chars
   CH_API_KEY       = votre-clé
   NAMESCAN_API_KEY = votre-clé
   ALLOWED_ORIGINS  = https://votre-frontend.vercel.app
   APP_URL          = https://votre-api.railway.app
   ```
6. Railway génère une URL : `https://complianceos-xxx.railway.app`

**3. Appliquer le schema DB**
Dans Railway → PostgreSQL → Connect → Run query → coller `db/init.sql`

---

### Option B — Render (gratuit pour tester)

Render a un free tier (API dort après 15min d'inactivité).

1. https://render.com → New Web Service → Connect GitHub
2. Build Command : `pip install -r requirements.txt`
3. Start Command : `cd api && uvicorn main:app --host 0.0.0.0 --port $PORT`
4. New PostgreSQL → copier l'URL dans les env vars
5. URL générée : `https://complianceos.onrender.com`

---

### Option C — VPS (Contabo/Hetzner, ~€4/mois)

Pour une prod sérieuse avec contrôle total :

```bash
# Sur le VPS (Ubuntu 22.04)
apt install python3.11 python3.11-venv postgresql nginx -y

# Clone du repo
git clone https://github.com/VOTRE_USERNAME/complianceos.git
cd complianceos
python3.11 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# PostgreSQL
sudo -u postgres createdb complianceos
sudo -u postgres psql complianceos < db/init.sql

# .env
cp .env.example .env && nano .env

# Lancer avec systemd (service permanent)
# → voir complianceos.service ci-dessous

# Nginx reverse proxy
# → voir nginx.conf ci-dessous

# SSL gratuit
apt install certbot python3-certbot-nginx -y
certbot --nginx -d api.complianceos.io
```

---

## FRONTEND — Déploiement sur Vercel (gratuit)

Le dashboard HTML peut être servi statiquement ou migré en Next.js.

**Pour le dashboard HTML statique :**
```bash
# Dans complianceos/frontend/
# Vercel CLI
npm i -g vercel
vercel deploy
# → URL : https://complianceos-dashboard.vercel.app
```

**Mettre à jour l'URL de l'API dans dashboard.html :**
Remplacer `http://localhost:8000` par l'URL Railway/Render.

---

## CHECKLIST PRODUCTION

- [ ] `JWT_SECRET` différent de dev (min 32 chars)
- [ ] `DATABASE_URL` pointe vers la prod
- [ ] `ALLOWED_ORIGINS` contient uniquement votre domaine frontend
- [ ] `APP_ENV=production` dans les env vars
- [ ] Schema DB appliqué (`db/init.sql`)
- [ ] HTTPS activé (Railway/Render le font automatiquement)
- [ ] Premier compte créé via `POST /auth/register`

---

## TEST RAPIDE DE L'API (curl)

```bash
# 1. Créer un compte
curl -X POST https://votre-url/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@firm.co.uk","password":"secure123","full_name":"Alex","company_name":"My Fintech","fca_firm_ref":"800001"}'

# 2. Login → récupérer access_token
curl -X POST https://votre-url/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@firm.co.uk","password":"secure123"}'

# 3. Stats dashboard
curl https://votre-url/api/v1/stats \
  -H "Authorization: Bearer VOTRE_TOKEN"

# 4. Lancer un KYB (Revolut)
curl -X POST https://votre-url/api/v1/kyb \
  -H "Authorization: Bearer VOTRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"company_number":"08804411"}'
```
