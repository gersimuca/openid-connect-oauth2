from django.core.management.base import BaseCommand
from apps.security.jwk_utils import gen_rsa_jwk
from apps.security.models import JWK
import json


class Command(BaseCommand):
    help = "Generate an RSA JWK and store it in the DB (private included)."

    def add_arguments(self, parser):
        parser.add_argument('--size', type=int, default=2048)

    def handle(self, *args, **options):
        size = options['size']
        jw = gen_rsa_jwk(key_size=size)
        kid = jw.get('kid')
        JWK.objects.all().update(active=False)  # deactivate others
        obj = JWK.objects.create(kid=kid, jwk_json=jw, active=True)
        self.stdout.write(self.style.SUCCESS(f"Created JWK kid={kid} size={size}"))
