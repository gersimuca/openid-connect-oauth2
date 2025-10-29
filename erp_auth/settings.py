import os
from pathlib import Path
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()  # loads .env file

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "change-me")
DEBUG = os.getenv("DJANGO_DEBUG", "True") == "True"

ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "127.0.0.1,localhost").split(",")

INSTALLED_APPS = [
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework',
    'apps.security',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
]

ROOT_URLCONF = 'erp_auth.urls'

TEMPLATES = [{
    'BACKEND': 'django.template.backends.django.DjangoTemplates',
    'DIRS': [],
    'APP_DIRS': True,
    'OPTIONS': {'context_processors': [
        'django.template.context_processors.debug',
        'django.template.context_processors.request',
        'django.contrib.auth.context_processors.auth',
        'django.contrib.messages.context_processors.messages',
    ]},
}]

WSGI_APPLICATION = 'erp_auth.wsgi.application'

# Database: support DATABASE_URL environment variable
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
if DATABASE_URL.startswith("sqlite"):
    # Django sqlite config
    DATABASES = {'default': {'ENGINE': 'django.db.backends.sqlite3', 'NAME': str(BASE_DIR / 'db.sqlite3')}}
else:
    # Simple URL parse for postgres/mysql
    url = urlparse(DATABASE_URL)
    ENGINE = 'django.db.backends.postgresql' if 'postgres' in url.scheme or 'postgresql' in url.scheme else 'django.db.backends.mysql'
    DATABASES = {
        'default': {
            'ENGINE': ENGINE,
            'NAME': url.path[1:],
            'USER': url.username,
            'PASSWORD': url.password,
            'HOST': url.hostname,
            'PORT': url.port or '',
        }
    }

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
]

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True
STATIC_URL = '/static/'
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# SSO / JWT settings
SSO_ISSUER = os.getenv('SSO_ISSUER', 'http://127.0.0.1:8000')
SSO_AUDIENCE = os.getenv('SSO_AUDIENCE', 'erp')
SSO_JWKS_PATH = os.getenv('SSO_JWKS_PATH', '/protocol/openid-connect/certs')

ACCESS_TOKEN_EXP = int(os.getenv('ACCESS_TOKEN_EXP', '3600'))  # seconds
REFRESH_TOKEN_EXP = int(os.getenv('REFRESH_TOKEN_EXP', str(14*24*3600)))  # seconds

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'apps.security.auth_utils.JWTAuthentication',  # our auth class
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
}

# Logging (simple)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {'console': {'class': 'logging.StreamHandler'}},
    'root': {'handlers': ['console'], 'level': 'INFO'},
}
