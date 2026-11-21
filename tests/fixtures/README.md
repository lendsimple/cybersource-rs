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

## Stage 3 fixtures (P12 and message-level encryption)

```sh
# Stand-in for Cybersource's request-MLE certificate, with its own key pair.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out sjc_test_key.pem
openssl req -new -x509 -key sjc_test_key.pem -days 36500 \
  -subj "/CN=CyberSource_SJC_US/serialNumber=SJC0000000001" -out sjc_cert.pem
# Cybersource-shaped merchant P12: plain KeyBag, 3DES cert bag, SHA-256 MAC, plus the SJC cert.
openssl pkcs12 -export -inkey rsa_test_key.pem -in merchant_cert.pem -certfile sjc_cert.pem -name testmerchant \
  -keypbe NONE -certpbe PBE-SHA1-3DES -macalg sha256 -passout pass:testmerchant -out cybs_shaped.p12
# Legacy P12: 3DES key bag, RC2-40 certificate bag, SHA-1 MAC.
openssl pkcs12 -export -legacy -inkey rsa_test_key.pem -in merchant_cert.pem -name testmerchant \
  -passout pass:testmerchant -out legacy.p12
# Response-MLE key: own key pair; cert CN = merchant id, serialNumber = the response-MLE kid.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out response_mle_key.pem
openssl req -new -x509 -key response_mle_key.pem -days 36500 \
  -subj "/CN=testmerchant/serialNumber=RESPMLE0000001" -out response_mle_cert.pem
openssl pkcs12 -export -inkey response_mle_key.pem -in response_mle_cert.pem -certfile sjc_cert.pem \
  -name testmerchant -passout pass:testmerchant-mle -out response_mle.p12
# Encrypted PKCS#8 (PBES2/PBKDF2-HMAC-SHA256/AES-256-CBC) and a PEM with an OpenSSL "Bag Attributes" preamble.
openssl pkcs8 -topk8 -in response_mle_key.pem -v2 aes-256-cbc -v2prf hmacWithSHA256 \
  -passout pass:secret-pw -out response_mle_key_encrypted.pem
{ printf 'Bag Attributes\n    friendlyName: testmerchant\nKey Attributes: <No Attributes>\n'; cat response_mle_key.pem; } \
  > response_mle_key_with_preamble.pem
# Cybersource-style certificate whose X.509 serial is 22 bytes (the ASCII digits of the decimal serial),
# over RFC 5280's 20-octet limit, as in Cybersource's real certificates.
openssl req -new -x509 -key rsa_test_key.pem -days 36500 \
  -set_serial 0x31373634333030343737343835303336393437313632 \
  -subj "/CN=testmerchant/serialNumber=1764300477485036947162" -out long_serial_cert.pem
```
