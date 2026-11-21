"""Generate authentication known-answer vectors from the official Cybersource Python SDK.

Run via `cargo xtask vectors`, which installs the pinned SDK into a venv and calls:

    python -I xtask/vectors/gen_vectors.py <fixtures_dir> <output_dir>

The SDK's own classes produce every expected value. For JWT, its calls to
`time.time()` and `uuid.uuid4()` are pinned by replacing the `time` and `uuid`
names inside `authenticationsdk.jwt.Token`, so the output is reproducible.
"""

import base64
import json
import logging
import os
import sys
import types
import uuid
from wsgiref.handlers import format_date_time

# The SDK's modules import each other circularly; importing the top-level
# package first (as SDK users do) resolves the cycle.
import CyberSource  # noqa: F401
from authenticationsdk.core.Authorization import Authorization
from authenticationsdk.core.MerchantConfiguration import MerchantConfiguration
from authenticationsdk.payloaddigest.PayLoadDigest import DigestAndPayload
import authenticationsdk.jwt.Token as sdk_token

HOST = "apitest.cybersource.com"
MERCHANT_ID = "testmerchant"
PORTFOLIO_ID = "testportfolio"
# Public sample credentials from CyberSource/cybersource-rest-samples-*. Not secret.
KEY_ID = "08c94330-f618-42a3-b09d-e1e43be5efda"
SECRET = "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE="
# 2026-11-05T08:00:00Z: a single-digit day, to pin zero-padded IMF-fixdate.
EPOCH = 1793865600
JTI = "11111111-1111-4111-9111-111111111111"
PAYMENT_BODY = json.dumps(
    {
        "clientReferenceInformation": {"code": "TC50171_3"},
        "paymentInformation": {
            "card": {"number": "4111111111111111", "expirationMonth": "12", "expirationYear": "2031"}
        },
        "orderInformation": {"amountDetails": {"totalAmount": "102.21", "currency": "USD"}},
    },
    separators=(",", ":"),
)


def merchant_config(auth_type, *, jwt_key_type=None, metakey=False, fixtures=None):
    values = {
        "authentication_type": auth_type,
        "merchantid": MERCHANT_ID,
        "run_environment": HOST,
        "merchant_keyid": KEY_ID,
        "merchant_secretkey": SECRET,
    }
    if jwt_key_type:
        values["jwt_key_type"] = jwt_key_type
    if metakey:
        values["use_metakey"] = True
        values["portfolio_id"] = PORTFOLIO_ID
    if fixtures:
        values["keys_directory"] = fixtures
        values["key_file_name"] = MERCHANT_ID
        values["key_alias"] = MERCHANT_ID
        values["key_password"] = MERCHANT_ID
    config = MerchantConfiguration()
    config.set_merchantconfig(values)
    # validate_merchant_details logs the dict via ast.literal_eval(json.dumps(...)),
    # which crashes on JSON `true`; the SDK has already read use_metakey above.
    config.validate_merchant_details({k: str(v) for k, v in values.items()})
    return config


def token(config, method, target, body):
    date = format_date_time(EPOCH)
    result = Authorization().get_token(config, date, method, target, body)
    if result is None:
        # Authorization.get_token logs and swallows errors; fail loudly instead.
        raise RuntimeError(f"SDK returned no token for {method} {target}")
    return date, result


def http_signature_vectors():
    cases = [
        ("get", "GET", "/pts/v2/payments/6789012345678901234567", None, False),
        ("post", "POST", "/pts/v2/payments", PAYMENT_BODY, False),
        ("get_with_query", "GET", "/reporting/v3/reports?startTime=2026-11-01T00%3A00%3A00Z&reportName=My%20Report", None, False),
        ("patch", "PATCH", "/tms/v2/customers/ABC123", '{"buyerInformation":{"email":"a@b.example"}}', False),
        ("delete", "DELETE", "/tms/v2/customers/ABC123", None, False),
        ("post_metakey", "POST", "/pts/v2/payments", PAYMENT_BODY, True),
    ]
    out = []
    for name, method, target, body, metakey in cases:
        config = merchant_config("http_signature", metakey=metakey)
        date, signature = token(config, method, target, body)
        out.append(
            {
                "name": name,
                "epoch": EPOCH,
                "method": method,
                "host": HOST,
                "target": target,
                "body": body,
                "merchant_id": MERCHANT_ID,
                "portfolio_id": PORTFOLIO_ID if metakey else None,
                "key_id": KEY_ID,
                "secret": SECRET,
                "expected_date": date,
                "expected_signature": signature,
            }
        )
    return out


def jwt_vectors(fixtures):
    sdk_token.time = types.SimpleNamespace(time=lambda: EPOCH)
    sdk_token.uuid = types.SimpleNamespace(uuid4=lambda: uuid.UUID(JTI))
    cases = [
        ("hs256_get", "SHARED_SECRET", "GET", "/pts/v2/payments/6789012345678901234567", None, False),
        ("hs256_post", "SHARED_SECRET", "POST", "/pts/v2/payments", PAYMENT_BODY, False),
        ("hs256_post_metakey", "SHARED_SECRET", "POST", "/pts/v2/payments", PAYMENT_BODY, True),
        ("rs256_post", "P12", "POST", "/pts/v2/payments", PAYMENT_BODY, False),
        ("rs256_get_with_query", "P12", "GET", "/reporting/v3/reports?startTime=2026-11-01T00%3A00%3A00Z", None, False),
    ]
    out = []
    for name, key_type, method, target, body, metakey in cases:
        config = merchant_config(
            "jwt",
            jwt_key_type=key_type,
            metakey=metakey,
            fixtures=fixtures if key_type == "P12" else None,
        )
        _, jwt = token(config, method, target, body)
        out.append(
            {
                "name": name,
                "alg": "HS256" if key_type == "SHARED_SECRET" else "RS256",
                "epoch": EPOCH,
                "jti": JTI,
                "method": method,
                "host": HOST,
                "target": target,
                "body": body,
                "merchant_id": MERCHANT_ID,
                "portfolio_id": PORTFOLIO_ID if metakey else None,
                "key_id": KEY_ID if key_type == "SHARED_SECRET" else None,
                "secret": SECRET if key_type == "SHARED_SECRET" else None,
                "key_pem": "rsa_test_key.pem" if key_type == "P12" else None,
                "cert_pem": "merchant_cert.pem" if key_type == "P12" else None,
                "expected_token": jwt,
            }
        )
    return out


def jwe_vectors(fixtures):
    """Tokens the SDK (and its JOSE library, jwcrypto) encrypt to our fixture
    CyberSource_SJC_US key; the Rust tests decrypt them with sjc_test_key.pem."""
    from authenticationsdk.util.MLEUtility import MLEUtility
    import authenticationsdk.util.MLEUtility as mle_module
    from jwcrypto import jwe, jwk

    mle_module.time = types.SimpleNamespace(time=lambda: EPOCH)
    config = merchant_config("jwt", jwt_key_type="P12", fixtures=fixtures)
    # The Cybersource-shaped fixture P12 carries a CyberSource_SJC_US certificate.
    config.key_file_name = "cybs_shaped"
    config.p12KeyFilePath = os.path.join(fixtures, "cybs_shaped.p12")
    wrapper = MLEUtility.encrypt_request_payload(config, PAYMENT_BODY, "application/json")
    out = [{
        "name": "sdk_mle_request",
        "source": "MLEUtility.encrypt_request_payload",
        "wrapper": wrapper,
        "token": json.loads(wrapper)["encryptedRequest"],
        "plaintext": PAYMENT_BODY,
    }]

    with open(os.path.join(fixtures, "sjc_cert.pem"), "rb") as f:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert = x509.load_pem_x509_certificate(f.read())
        public = jwk.JWK.from_pem(cert.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    for name, alg, enc in [
        ("jwcrypto_rsa_oaep_a256gcm", "RSA-OAEP", "A256GCM"),
        ("jwcrypto_rsa_oaep_256_a128gcm", "RSA-OAEP-256", "A128GCM"),
        ("jwcrypto_rsa_oaep_256_a192gcm", "RSA-OAEP-256", "A192GCM"),
    ]:
        token = jwe.JWE(plaintext=PAYMENT_BODY.encode(), protected=json.dumps({"alg": alg, "enc": enc}))
        token.add_recipient(public)
        out.append({
            "name": name,
            "source": "jwcrypto",
            "token": token.serialize(compact=True),
            "plaintext": PAYMENT_BODY,
        })
    return out


def digest_vectors():
    bodies = ["{}", PAYMENT_BODY, '{"name":"café"}']
    return [
        {"body": b, "expected": DigestAndPayload().string_digest_generation(b).decode()}
        for b in bodies
    ]


def write(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def main():
    fixtures, output = sys.argv[1], sys.argv[2]
    logging.disable(logging.CRITICAL)
    write(os.path.join(output, "http_signature.json"), http_signature_vectors())
    write(os.path.join(output, "jwt.json"), jwt_vectors(fixtures))
    write(os.path.join(output, "digest.json"), digest_vectors())
    # Encryption is randomized, so these tokens differ on every run; keep the
    # committed ones unless the file is deleted (tests only decrypt them).
    jwe_path = os.path.join(output, "jwe.json")
    if not os.path.exists(jwe_path):
        write(jwe_path, jwe_vectors(fixtures))


if __name__ == "__main__":
    main()
