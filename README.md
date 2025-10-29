# Authentication Service

**OpenID Connect (OIDC) and OAuth2 Authentication Server**

This project implements a fully custom **authentication and authorization service** using **Django** and **Django REST Framework**.
It provides secure user authentication, token generation (JWT), and OpenID Connect discovery endpoints, designed for integration with Spring Boot or any OAuth2-compliant resource server.

---

## Overview

This service provides the following functionality:

* User registration and credential management
* OAuth2 password grant authentication flow
* JWT-based access tokens signed with RSA keys (RS256)
* OpenID Connect discovery and JWKS endpoints for resource servers
* Integration-ready with Spring Security or any OAuth2 client

---

## Requirements

| Dependency            | Version            |
| --------------------- | ------------------ |
| Python                | ≥ 3.10             |
| Django                | ≥ 4.2, < 5         |
| Django REST Framework | ≥ 3.14             |
| PyJWT                 | ≥ 2.8              |
| jwcrypto              | ≥ 1.4              |
| cryptography          | ≥ 41.0             |
| python-dotenv         | ≥ 1.0              |
| bcrypt                | ~ 5.0              |
| psycopg2-binary       | ≥ 2.9 (PostgreSQL) |

---

## Project Structure

```
openid-connect-oauth2/
│
├── manage.py
├── .env
├── requirements.txt
├── erp_auth/                     # Django project settings
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
│
└── apps/
    └── security/
        ├── models.py             # User model
        ├── auth_utils.py         # JWT and password utilities
        ├── views.py              # API views
        ├── urls_auth.py          # OAuth endpoints (/oauth/*)
        ├── urls_wellknown.py     # OpenID discovery endpoints
        └── keys/                 # RSA private.pem / public.pem
```

---

## Setup Guide

### 1. Clone the repository

```bash
git clone https://github.com/gersimuca/openid-connect-oauth2.git
cd openid-connect-oauth2
```

---

### 2. Create and activate a virtual environment

#### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

#### macOS / Linux

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

### 4. Generate RSA keys

These keys are used for signing and verifying JWT tokens.

```bash
mkdir -p apps/security/keys
openssl genrsa -out apps/security/keys/private.pem 2048
openssl rsa -in apps/security/keys/private.pem -pubout -out apps/security/keys/public.pem
```

Ensure that both files exist:

* `private.pem`
* `public.pem`

Never commit these files to version control.

---

### 5. Configure environment variables

Create a `.env` file in the project root:

```env
DEBUG=True
SECRET_KEY=your_django_secret_key_here
ALLOWED_HOSTS=*
DATABASE_URL=postgres://user:password@localhost:5432/erp_auth
```

If not using PostgreSQL, update your database configuration in `erp_auth/settings.py`.

---

### 6. Apply migrations

Run initial migrations to create database tables:

```bash
python manage.py makemigrations
python manage.py migrate
```

---

### 7. Run the application

Start the Django development server:

```bash
python manage.py runserver
```

Access it at: [http://localhost:8000](http://localhost:8000)

---

## API Endpoints

| Endpoint                            | Method | Description                         |
| ----------------------------------- | ------ | ----------------------------------- |
| `/oauth/register`                   | POST   | Register a new user                 |
| `/oauth/token`                      | POST   | Obtain JWT via password grant       |
| `/.well-known/openid-configuration` | GET    | OpenID Connect discovery document   |
| `/oauth/jwks.json`                  | GET    | JWKS endpoint (public signing keys) |

---

### Register a User

```bash
curl -X POST http://localhost:8000/oauth/register \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"alice\", \"email\": \"alice@example.com\", \"password\": \"mypassword123\"}"
```

**Response:**

```json
{"message": "User registered."}
```

---

### Request an Access Token (Password Grant)

```bash
curl -X POST http://localhost:8000/oauth/token \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"alice\", \"password\": \"mypassword123\"}"
```

**Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

---

### View OpenID Discovery Document

```bash
curl http://localhost:8000/.well-known/openid-configuration
```

**Response:**

```json
{
  "issuer": "http://localhost:8000",
  "authorization_endpoint": "http://localhost:8000/oauth/authorize",
  "token_endpoint": "http://localhost:8000/oauth/token",
  "jwks_uri": "http://localhost:8000/oauth/jwks.json",
  "response_types_supported": ["code", "token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"]
}
```

---

### Decode and Verify Token

Tokens can be decoded and verified using your `public.pem` file or an online tool such as [jwt.io](https://jwt.io/).

Example decoded payload:

```json
{
  "iss": "http://localhost:8000",
  "sub": "alice",
  "iat": 1730216578,
  "exp": 1730218378
}
```

---

## Integration Guide

### 1. Spring Boot (Resource Server Integration)

In your Spring Boot application, configure the following in `application.yml`:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:8000/oauth/jwks.json
```

This instructs Spring Security to validate all incoming JWTs against your Django authentication server’s public key.

After this, any valid token issued by your Django Auth Service will be accepted by your Spring Boot application.

---

### 2. Using with Other Microservices

For all API requests to your resource servers, include the token in the `Authorization` header:

```
Authorization: Bearer <access_token>
```

Each microservice should verify the token against the JWKS URI (`/oauth/jwks.json`).

---

### 3. Testing Token-Protected Endpoints

Once you add a protected API (for example `/api/userinfo`), test access using:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/userinfo
```

---

## Developer Tools

**Create a user manually via Django shell:**

```bash
python manage.py shell
```

```python
from apps.security.models import User
from apps.security.auth_utils import hash_password

user = User(username="admin", email="admin@example.com", password=hash_password("admin123"))
user.save()
exit()
```

**Reset database:**

```bash
python manage.py flush
```

**Create Django superuser (for admin access):**

```bash
python manage.py createsuperuser
```

---

## Security Guidelines

* Always set `DEBUG=False` in production.
* Use HTTPS in production environments.
* Never commit RSA private keys (`private.pem`) or `.env` files to version control.
* Use a strong Django `SECRET_KEY`.
* Rotate JWT signing keys periodically.

---

## License

This project is distributed under the MIT License.