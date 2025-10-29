import json
import time
from django.conf import settings
from django.http import JsonResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from apps.security.models import JWK, AccessToken, RefreshToken, Client
from apps.security.serializers import UserInfoSerializer
from apps.security.auth_utils import sign_access_token, generate_refresh_token, validate_access_token, \
    revoke_refresh_token, check_client_secret, hash_client_secret
from django.contrib.auth import authenticate, get_user_model
from jwcrypto import jwk as jwcrypto_jwk

User = get_user_model()


# --- Well-known OIDC metadata endpoint ---
class WellKnownView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        base = settings.SSO_ISSUER.rstrip('/')
        jwks_uri = base + settings.SSO_JWKS_PATH
        data = {
            "issuer": settings.SSO_ISSUER,
            "authorization_endpoint": base + "/protocol/openid-connect/auth",
            "token_endpoint": base + "/protocol/openid-connect/token",
            "userinfo_endpoint": base + "/protocol/openid-connect/userinfo",
            "introspection_endpoint": base + "/protocol/openid-connect/introspect",
            "revocation_endpoint": base + "/protocol/openid-connect/revoke",
            "jwks_uri": jwks_uri,
            "response_types_supported": ["code", "token", "id_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        return Response(data)


# --- JWKS endpoint ---
class JwksView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def get(self, request):
        keys = []
        for jw in JWK.objects.filter(active=True).order_by('-created_at'):
            keys.append(jw.public_jwk())
        return Response({"keys": keys})


# --- Token endpoint ---
class TokenView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        grant_type = request.data.get('grant_type')
        if grant_type == 'client_credentials':
            return self._client_credentials(request)
        elif grant_type == 'password':
            return self._password(request)
        elif grant_type == 'refresh_token':
            return self._refresh(request)
        else:
            return Response({"error": "unsupported_grant_type"}, status=status.HTTP_400_BAD_REQUEST)

    def _client_credentials(self, request):
        client_id = request.data.get('client_id')
        client_secret = request.data.get('client_secret')
        if not client_id or not client_secret:
            return Response({"error": "invalid_client"}, status=status.HTTP_401_UNAUTHORIZED)
        client = Client.objects.filter(client_id=client_id).first()
        if not client:
            return Response({"error": "invalid_client"}, status=status.HTTP_401_UNAUTHORIZED)
        if client.client_type == 'confidential':
            if not check_client_secret(client_secret, client.client_secret_hash):
                return Response({"error": "invalid_client"}, status=status.HTTP_401_UNAUTHORIZED)
        # create access token
        token, at_obj = sign_access_token(user=None, client=client, scope="")
        return Response({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXP,
        })

    def _password(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        client_id = request.data.get('client_id')
        client = Client.objects.filter(client_id=client_id).first() if client_id else None

        user = authenticate(username=username, password=password)
        if not user:
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        token, at_obj = sign_access_token(user=user, client=client, scope="openid profile email")
        refresh_token, rt_obj = generate_refresh_token(at_obj)
        return Response({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXP,
            "refresh_token": refresh_token,
        })

    def _refresh(self, request):
        rtoken = request.data.get('refresh_token')
        if not rtoken:
            return Response({"error": "invalid_request"}, status=status.HTTP_400_BAD_REQUEST)
        rt = RefreshToken.objects.filter(token=rtoken, revoked=False).first()
        if not rt:
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        if rt.is_expired():
            return Response({"error": "invalid_grant"}, status=status.HTTP_400_BAD_REQUEST)
        user = rt.access_token.user
        client = rt.access_token.client
        # create new access token
        token, new_at = sign_access_token(user=user, client=client, scope=rt.access_token.scope)
        # revoke old refresh token and create new one
        rt.revoked = True
        rt.save()
        new_refresh_token, new_rt = generate_refresh_token(new_at)
        return Response({
            "access_token": token,
            "token_type": "Bearer",
            "expires_in": settings.ACCESS_TOKEN_EXP,
            "refresh_token": new_refresh_token,
        })


# --- UserInfo endpoint ---
class UserInfoView(APIView):
    permission_classes = [permissions.AllowAny]  # token will be required in header
    authentication_classes = []

    def get(self, request):
        auth = request.headers.get('Authorization')
        if not auth:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        parts = auth.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        token = parts[1]
        try:
            claims = validate_access_token(token)
        except Exception:
            return Response(status=status.HTTP_401_UNAUTHORIZED)
        # map claims to user info
        sub = claims.get('sub')
        user = None
        if sub:
            try:
                user = User.objects.get(pk=int(sub))
            except Exception:
                # optional: create ephemeral user
                user = User.objects.filter(username=f"external:{sub}").first()
        if user:
            data = UserInfoSerializer(user).data
        else:
            data = {
                'sub': sub,
                'preferred_username': claims.get('preferred_username'),
            }
        return Response(data)


# --- Introspection ---
class IntrospectView(APIView):
    permission_classes = [permissions.AllowAny]  # client auth could be added
    authentication_classes = []

    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({"active": False})
        try:
            claims = validate_access_token(token)
            # check DB if token revoked or expired
            at = AccessToken.objects.filter(token=token).first()
            if at and at.is_expired():
                return Response({"active": False})
            active = True
        except Exception:
            active = False
            claims = {}
        response = {"active": active}
        if active:
            response.update({
                'iss': claims.get('iss'),
                'sub': claims.get('sub'),
                'aud': claims.get('aud'),
                'exp': claims.get('exp'),
                'iat': claims.get('iat'),
                'scope': claims.get('scope'),
            })
        return Response(response)


# --- Revoke endpoint ---
class RevokeView(APIView):
    permission_classes = [permissions.AllowAny]
    authentication_classes = []

    def post(self, request):
        token = request.data.get('token')
        token_type_hint = request.data.get('token_type_hint')
        if not token:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        # try refresh token first
        if revoke_refresh_token(token):
            return Response(status=status.HTTP_200_OK)
        # try access token in DB (delete)
        at = AccessToken.objects.filter(token=token).first()
        if at:
            at.delete()
            return Response(status=status.HTTP_200_OK)
        return Response(status=status.HTTP_200_OK)  # per spec, response is 200 even if token unknown
