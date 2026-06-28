# Notizen-Backend

FastAPI Backend für die Notizen-App – Deploy auf Render.com.

## Lokale Entwicklung

```bash
pip install -r requirements.txt
uvicorn main:app --reload
# API Docs: http://localhost:8000/docs
```

## Deploy auf Render.com

1. Repo auf GitHub pushen
2. [render.com](https://render.com) → New → Web Service → Repo verbinden
3. Oder: `render.yaml` wird automatisch erkannt (Blueprint)

**Pflicht-Umgebungsvariablen:**

| Variable | Beschreibung | Beispiel |
|----------|-------------|---------|
| `SECRET_KEY` | JWT-Signing-Key (min. 32 Zeichen) | Render generiert automatisch |
| `ALLOWED_ORIGINS` | CORS-Origins (kommagetrennt) | `https://Michdo93.github.io` |
| `RENDER` | Aktiviert /data Pfad für SQLite | `true` |

## API-Endpunkte

| Methode | Pfad | Beschreibung |
|---------|------|-------------|
| POST | `/auth/register` | Registrierung (erster User = Admin) |
| POST | `/auth/login` | Login → JWT-Token |
| GET | `/auth/me` | Eigenes Profil |
| GET | `/notizen` | Alle eigenen Notizen (Filter: search, pinned) |
| POST | `/notizen` | Neue Notiz |
| PUT | `/notizen/{id}` | Notiz bearbeiten |
| DELETE | `/notizen/{id}` | Notiz löschen |
| GET | `/admin/users` | Alle User (Admin) |
| PATCH | `/admin/users/{id}/toggle-active` | User sperren/entsperren |
| PATCH | `/admin/users/{id}/toggle-admin` | Admin-Rechte vergeben |
| DELETE | `/admin/users/{id}` | User löschen |
| GET | `/admin/stats` | Statistiken |

## Datenbank

SQLite via SQLAlchemy. Auf Render.com wird `/data/notizen.db` auf einer Persistent Disk gespeichert (1 GB kostenlos). Kein separater DB-Service nötig.

## Sicherheit

- Passwörter mit bcrypt gehasht
- JWT-Token mit konfigurierbarer Laufzeit (Standard: 7 Tage)
- Erster registrierter User wird automatisch Admin
- CORS auf Frontend-Origin eingeschränkt
