import json
import uuid
from jwcrypto import jwk


def gen_rsa_jwk(key_size=2048):
    key = jwk.JWK.generate(kty='RSA', size=key_size)
    kid = str(uuid.uuid4())
    # export full jwk (private and public)
    jw = json.loads(key.export(private_keys=True, as_dict=False) if False else key.export(as_dict=True))
    # the jwcrypto export() returns dict for as_dict=True
    jw['kid'] = kid
    return jw
