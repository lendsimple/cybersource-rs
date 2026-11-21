# Authentication vectors

Every expected value in this directory was produced by the **official Cybersource Python SDK**,
`cybersource-rest-client-python` **0.0.81** (PyPI), running its own `authenticationsdk` code.
Regenerate with:

```sh
cargo xtask vectors
```

`xtask` installs the pinned SDK into `target/xtask/venv` (network needed once) and runs
[`xtask/vectors/gen_vectors.py`](../../xtask/vectors/gen_vectors.py). Re-running must produce no diff.

| File | SDK code path | Notes |
|---|---|---|
| `http_signature.json` | `Authorization.get_token` → `HTTPSignatureToken` | GET, POST, GET with query, PATCH, DELETE, meta key. The date is passed in by the caller (the SDK formats it with `wsgiref.handlers.format_date_time`). |
| `jwt.json` | `Authorization.get_token` → `JwtSignatureToken` | HS256 (`jwt_key_type=SHARED_SECRET`) and RS256 (`P12`, using `tests/fixtures/testmerchant.p12`). |
| `jwe.json` | `MLEUtility.encrypt_request_payload` (with `tests/fixtures/cybs_shaped.p12`) and jwcrypto directly | Encrypted to the fixture `CyberSource_SJC_US` key; the tests decrypt with `sjc_test_key.pem`. Encryption is randomized, so the generator only writes this file when it is missing: delete it to regenerate. |
| `digest.json` | `DigestAndPayload.string_digest_generation` | Includes non-ASCII to pin UTF-8 hashing. |

Determinism:

- The SDK's JWT code calls `time.time()` and `uuid.uuid4()`. The generator replaces the `time` and
  `uuid` names inside `authenticationsdk.jwt.Token` with fixed values (`epoch`, `jti` in each vector).
- jwcrypto serializes JWT headers and claims compactly with sorted keys, so our tokens are compared
  **byte for byte**, not just semantically.
- Instant used: `1793865600` = Thu, 05 Nov 2026 08:00:00 GMT (single-digit day of month, to pin the
  zero-padded IMF-fixdate).

Credentials are the public sample credentials from `CyberSource/cybersource-rest-samples-*`, with a
made-up merchant ID; the RSA key is the throwaway fixture in `tests/fixtures/`.

SDK quirks worked around in the generator (none affect the vectors' content):

- Its modules import each other circularly; importing the top-level `CyberSource` package first avoids it.
- `MerchantConfiguration.validate_merchant_details` crashes when a config value is a Python bool
  (`ast.literal_eval` on JSON `true`), so the dict passed to validation is stringified.
- `Authorization.get_token` swallows exceptions and returns `None`; the generator raises instead.
