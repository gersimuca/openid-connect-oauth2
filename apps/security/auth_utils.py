import time, json
from datetime import datetime, timedelta
import jwt
from django.conf import settings
from jwcrypto import jwk
from apps.security.models import JWK, AccessToken, RefreshToken, Client
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework import authentication, exceptions
from jwt import PyJWKClient
import requests
from django.utils.crypto import get_random_string
import hashlib
import bcrypt

User = get_user_model()


def _get_active_jwk_object():
    jwk_obj = JWK.objects.filter(active=True).order_by('-created_at').first()
    if jwk_obj is None:
        raise RuntimeError("No active JWK found. Run `manage.py genjwk`")
    return jwk_obj


def _private_key_for_jwk(jw_dict):
    # create jwcrypto JWK and export PEM private key
    jw = jwk.JWK.from_json(json.dumps(jw_dict))
    pem = jw.export_to_pem(private_key=True, password=None)
    return pem


def _public_key_for_jwk(jw_dict):
    jw = jwk.JWK.from_json(json.dumps(jw_dict))
    pem = jw.export_to_pem(private_key=False)
    return pem


def sign_access_token(user=None, client=None, scope=''):
    """
    Create an RS256 signed JWT access token using the currently active JWK.
    """
    jwk_obj = _get_active_jwk_object()
    payload = {
        'iss': settings.SSO_ISSUER,
        'aud': settings.SSO_AUDIENCE,
        'iat': int(time.time()),
        'exp': int(time.time()) + settings.ACCESS_TOKEN_EXP,
        'scope': scope,
    }
    if user:
        payload['sub'] = str(user.id)
        payload['preferred_username'] = user.username
    else:
        payload['sub'] = client.client_id if client else 'service'
    private_pem = _private_key_for_jwk(jwk_obj.jwk_json)
    headers = {'kid': jwk_obj.kid}
    token = jwt.encode(payload, private_pem, algorithm='RS256', headers=headers)
    # persist token
    at = AccessToken.objects.create(
        token=token,
        user=user,
        client=client,
        scope=scope,
        expires_at=timezone.now() + timedelta(seconds=settings.ACCESS_TOKEN_EXP),
    )
    return token, at


def generate_refresh_token(access_token_obj):
    token = get_random_string(64)
    rt = RefreshToken.objects.create(
        token=token,
        access_token=access_token_obj,
        expires_at=timezone.now() + timedelta(seconds=settings.REFRESH_TOKEN_EXP)
    )
    return token, rt


def revoke_refresh_token(token_str):
    try:
        rt = RefreshToken.objects.get(token=token_str)
    except RefreshToken.DoesNotExist:
        return False
    rt.revoked = True
    rt.save()
    # also delete associated access token in DB (optional)
    rt.access_token.delete()
    return True


def validate_access_token(token):
    """
    Validate token signature + claims using present active and previous JWKs.
    We will search JWKS in DB and try to verify against public keys.
    Returns decoded payload on success or raises jwt.InvalidTokenError.
    """
    # First try PyJWKClient against our own JWKS endpoint (faster: reuse HTTP cache)
    jwks_uri = (settings.SSO_ISSUER.rstrip('/') + settings.SSO_JWKS_PATH)
    try:
        jwk_client = PyJWKClient(jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(token)
        payload = jwt.decode(token, signing_key.key, algorithms=["RS256"], audience=settings.SSO_AUDIENCE,
                             issuer=settings.SSO_ISSUER)
        return payload
    except Exception:
        # fallback: iterate DB keys
        for jw in JWK.objects.filter(active=True).order_by('-created_at'):
            try:
                pub_pem = _public_key_for_jwk(jw.jwk_json)
                payload = jwt.decode(token, pub_pem, algorithms=["RS256"], audience=settings.SSO_AUDIENCE,
                                     issuer=settings.SSO_ISSUER)
                return payload
            except Exception:
                continue
        raise


class JWTAuthentication(authentication.BaseAuthentication):
    """
    Use this class in resource servers to validate Bearer tokens.
    It will use PyJWKClient to fetch JWKS from the SSO_ISSUER + SSO_JWKS_PATH.
    """

    def authenticate(self, request):
        auth_header = request.headers.get('Authorization') or request.META.get('HTTP_AUTHORIZATION')
        if not auth_header:
            return None
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            raise exceptions.AuthenticationFailed('Invalid authorization header')
        token = parts[1]
        try:
            payload = validate_access_token(token)
        except Exception as e:
            raise exceptions.AuthenticationFailed(f'Token validation failed: {str(e)}')
        # map sub to user or create ephemeral user
        sub = payload.get('sub')
        user = None
        if sub:
            # try numeric id first
            try:
                user = User.objects.filter(pk=int(sub)).first()
            except Exception:
                user = User.objects.filter(username=f"external:{sub}").first()
            if user is None:
                # create a lightweight user record for remote subject
                user = User.objects.create(username=f"external:{sub}")
        else:
            raise exceptions.AuthenticationFailed('sub claim missing')

        # attach token and claims for view usage
        user.jwt_claims = payload
        return user, None


# client secret hashing utilities
def hash_client_secret(plain_secret: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(plain_secret.encode(), salt)
    return hashed.decode()


def check_client_secret(plain_secret: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain_secret.encode(), hashed.encode())
    except Exception:
        return False
