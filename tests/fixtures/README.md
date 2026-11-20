# Test fixtures

Throwaway keys and certificates generated for tests. They protect nothing; do not use them anywhere else.

Regenerate with OpenSSL (any change invalidates the committed vectors in `tests/vectors/`; run `cargo xtask vectors` afterwards):

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa_test_key.pem          # PKCS#8
openssl rsa -in rsa_test_key.pem -traditional -out rsa_test_key_pkcs1.pem                   # PKCS#1
openssl req -new -x509 -key rsa_test_key.pem -days 36500 \
  -subj "/C=US/O=cybersource-rs tests/CN=testmerchant/serialNumber=1234567890ABCDEF" -out merchant_cert.pem
openssl req -new -x509 -key rsa_test_key.pem -days 36500 \
  -subj "/C=US/O=cybersource-rs tests/CN=testmerchant" -out cert_without_serial.pem
```

`merchant_cert.pem` mimics a Cybersource merchant certificate: the JWT `kid` is the subject DN's
`serialNumber` attribute (`1234567890ABCDEF`), not the X.509 serial number.

`rs256_known_answer.txt` is the compact JWS for header `{"alg":"RS256","kid":"k1","typ":"JWT"}` and
payload `{"a":1}`, signed with `rsa_test_key.pem` by OpenSSL (`openssl dgst -sha256 -sign`).
RSASSA-PKCS1-v1_5 is deterministic, so our signer must reproduce it exactly.

`testmerchant.p12` bundles the key and `merchant_cert.pem` the way a Cybersource-issued P12 does
(alias = merchant ID `testmerchant`, password = merchant ID). The official Python SDK signs the RS256
vectors with it:

```sh
openssl pkcs12 -export -inkey rsa_test_key.pem -in merchant_cert.pem -name testmerchant \
  -passout pass:testmerchant -out testmerchant.p12
```
