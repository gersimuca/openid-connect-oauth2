from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
import json

User = get_user_model()


class Client(models.Model):
    CLIENT_TYPE_CHOICES = (('confidential', 'confidential'), ('public', 'public'))
    client_id = models.CharField(max_length=200, unique=True)
    client_secret_hash = models.CharField(max_length=512, blank=True, null=True)  # hashed secret
    name = models.CharField(max_length=200, blank=True)
    redirect_uris = models.TextField(blank=True, help_text="space-separated URIs")
    grant_types = models.TextField(default='authorization_code password client_credentials refresh_token')
    client_type = models.CharField(max_length=20, choices=CLIENT_TYPE_CHOICES, default='confidential')
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.client_id


class JWK(models.Model):
    kid = models.CharField(max_length=200, unique=True)
    jwk_json = models.JSONField()  # store whole jwk json (private+public). Protect in prod.
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def public_jwk(self):
        # Return public-only part for the JWKS endpoint
        jw = dict(self.jwk_json)
        # Remove private fields (if present)
        for p in ('d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'):
            jw.pop(p, None)
        return jw


class AccessToken(models.Model):
    token = models.TextField(unique=True)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE)
    client = models.ForeignKey(Client, null=True, blank=True, on_delete=models.CASCADE)
    scope = models.TextField(blank=True)
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return self.expires_at <= timezone.now()


class RefreshToken(models.Model):
    token = models.CharField(max_length=512, unique=True)
    access_token = models.OneToOneField(AccessToken, on_delete=models.CASCADE)
    revoked = models.BooleanField(default=False)
    issued_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()

    def is_expired(self):
        return self.expires_at <= timezone.now()
