//! Flex API client-side tokenization: request building and response parsing.
//! Runs natively and on wasm (see tests/wasm.rs for the commands).

#![cfg(feature = "server")]

use cybersource::entropy::OsEntropy;
use cybersource::flex::{
    CaptureContext, CardData, FlexError, parse_tokenize_response, tokenize_request,
};
use cybersource::jose::jwe::{self, KeyAlg};
use cybersource::jose::jwk::RsaJwk;
use cybersource::jose::jws::{self, JwsKey};
use cybersource::keys::pem::rsa_private_key_from_pem;
use rsa::PrivateKey;
use serde_json::{Value, json};

const NOW: i64 = 1_793_865_600;

macro_rules! wasm_test {
    ($(#[$meta:meta])* fn $name:ident() $body:block) => {
        $(#[$meta])*
        #[cfg_attr(all(target_arch = "wasm32", target_os = "unknown"), wasm_bindgen_test::wasm_bindgen_test)]
        #[cfg_attr(not(all(target_arch = "wasm32", target_os = "unknown")), test)]
        fn $name() $body
    };
}

fn signer() -> PrivateKey {
    rsa_private_key_from_pem(include_str!("fixtures/rsa_test_key.pem")).unwrap()
}

/// The capture context's one-time key; Cybersource holds the private half.
fn one_time() -> PrivateKey {
    rsa_private_key_from_pem(include_str!("fixtures/sjc_test_key.pem")).unwrap()
}

fn context_with(kind: &str, exp: i64, data: Value) -> CaptureContext {
    let jwk = RsaJwk::from_public_key(
        &one_time().to_public_key(),
        Some("08ajMBidgTrHvGJVzpR3ZxrNylkXqVA3".into()),
    );
    let jwt = jws::sign(
        JwsKey::Rs256(&signer()),
        "zu",
        &json!({
            "iss": "Flex API", "iat": exp - 900, "exp": exp, "jti": "ctx-1",
            "flx": { "path": "/flex/v2/tokens", "data": "opaque", "origin": "https://testflex.cybersource.com", "jwk": jwk },
            "ctx": [{ "type": kind, "data": data }],
        }),
    )
    .unwrap();
    CaptureContext::parse_unverified(&jwt).unwrap()
}

fn api_context() -> CaptureContext {
    context_with(
        "api-0.1.0",
        NOW + 900,
        json!({
            "requiredFields": [
                "paymentInformation.card.number",
                "paymentInformation.card.expirationMonth",
                "paymentInformation.card.expirationYear",
            ],
            "optionalFields": ["paymentInformation.card.securityCode", "orderInformation.billTo.postalCode"],
        }),
    )
}

fn card() -> CardData {
    CardData::new("4111111111111111", "12", "2031").security_code("123")
}

wasm_test! {
    fn request_is_an_encrypted_payload_for_the_contexts_key() {
        let context = api_context();
        let req = tokenize_request(&context, &card().bill_to("postalCode", "94105"), NOW, &OsEntropy).unwrap();
        assert_eq!(req.url, "https://testflex.cybersource.com/flex/v2/tokens");
        assert_eq!(req.content_type, "application/json; charset=utf-8");
        assert!(!req.body.contains("4111"), "card data must only travel encrypted");

        let body: Value = serde_json::from_str(&req.body).unwrap();
        let token = body["keyId"].as_str().unwrap();
        let decrypted = jwe::decrypt(&one_time(), token, &[KeyAlg::RsaOaep]).unwrap();
        assert_eq!(decrypted.header["alg"], "RSA-OAEP");
        assert_eq!(decrypted.header["enc"], "A256GCM");
        assert_eq!(decrypted.header["kid"], "08ajMBidgTrHvGJVzpR3ZxrNylkXqVA3");

        let plaintext: Value = serde_json::from_slice(&decrypted.plaintext).unwrap();
        assert_eq!(
            plaintext["data"],
            json!({
                "paymentInformation": { "card": {
                    "number": "4111111111111111", "securityCode": "123",
                    "expirationMonth": "12", "expirationYear": "2031",
                } },
                "orderInformation": { "billTo": { "postalCode": "94105" } },
            })
        );
        assert_eq!(plaintext["context"], context.jwt);
        assert_eq!(plaintext["index"], 0);
        assert_eq!(plaintext["iat"], NOW);
        assert_eq!(plaintext["jti"].as_str().unwrap().len(), 32);
    }
}

wasm_test! {
    fn required_and_allowed_fields_are_enforced() {
        let context = api_context();
        let mut no_expiry = card();
        no_expiry.expiration_month = None;
        assert_eq!(
            tokenize_request(&context, &no_expiry, NOW, &OsEntropy).unwrap_err(),
            FlexError::MissingRequiredField("paymentInformation.card.expirationMonth".into())
        );
        assert_eq!(
            tokenize_request(&context, &card().bill_to("email", "a@b.c"), NOW, &OsEntropy).unwrap_err(),
            FlexError::FieldNotAllowed("orderInformation.billTo.email".into())
        );
    }
}

wasm_test! {
    fn only_flex_api_contexts_can_be_tokenized_directly() {
        for kind in ["mf-2.1.0", "gda-0.10.0"] {
            let context = context_with(kind, NOW + 900, json!({}));
            assert_eq!(
                tokenize_request(&context, &card(), NOW, &OsEntropy).unwrap_err(),
                FlexError::UnsupportedContextType(kind.into())
            );
        }
    }
}

wasm_test! {
    fn expired_contexts_are_refused_before_encrypting() {
        let context = context_with("api-0.1.0", NOW - 60, json!({}));
        assert_eq!(tokenize_request(&context, &card(), NOW, &OsEntropy).unwrap_err(), FlexError::Expired);
    }
}

wasm_test! {
    fn context_lists_its_fields() {
        let context = api_context();
        assert_eq!(context.kind(), Some("api-0.1.0"));
        assert_eq!(context.required_fields().len(), 3);
        assert_eq!(context.optional_fields()[1], "orderInformation.billTo.postalCode");
    }
}

fn transient_token() -> String {
    jws::sign(
        JwsKey::Rs256(&one_time()),
        "08ajMBidgTrHvGJVzpR3ZxrNylkXqVA3",
        &json!({
            "iss": "Flex/08", "iat": NOW, "exp": NOW + 900, "type": "api-0.1.0", "jti": "tt-1",
            "content": { "paymentInformation": { "card": { "number": { "maskedValue": "XXXXXXXXXXXX1111", "bin": "411111" } } } },
        }),
    )
    .unwrap()
}

wasm_test! {
    fn success_body_is_the_transient_token() {
        let jwt = transient_token();
        // As testflex sends it (2026-11), and the bare and quoted forms.
        let observed = json!({ "_embedded": {}, "discoverableServices": {}, "timestamp": 0, "token": jwt }).to_string();
        for body in [observed, jwt.clone(), format!("{jwt}\n"), serde_json::to_string(&jwt).unwrap()] {
            let token = parse_tokenize_response(201, body.as_bytes()).unwrap();
            assert_eq!(token.jwt, jwt);
            assert_eq!(token.jti.as_deref(), Some("tt-1"));
        }
        assert!(matches!(
            parse_tokenize_response(200, br#"{"timestamp":0}"#).unwrap_err(),
            FlexError::InvalidResponse(_)
        ));
        // ...and the server can verify it against the context's key.
        let verified = api_context().verify_transient_token(&jwt, NOW).unwrap();
        assert_eq!(verified.content.unwrap()["paymentInformation"]["card"]["number"]["bin"], "411111");
    }
}

wasm_test! {
    fn both_error_shapes_are_reported() {
        let nested = br#"{"responseStatus":{"status":400,"reason":"VALIDATION_ERROR","message":"Validation error","correlationId":"c-1","details":[{"location":"paymentInformation.card.number","message":"Invalid"}]}}"#;
        match parse_tokenize_response(400, nested).unwrap_err() {
            FlexError::Rejected { status, reason, correlation_id, details, .. } => {
                assert_eq!((status, reason.as_str()), (400, "VALIDATION_ERROR"));
                assert_eq!(correlation_id.as_deref(), Some("c-1"));
                assert_eq!(details.len(), 1);
            }
            other => panic!("{other:?}"),
        }
        let flat = br#"{"reason":"CAPTURE_CONTEXT_EXPIRED","message":"expired","correlationId":"c-2"}"#;
        assert!(matches!(
            parse_tokenize_response(400, flat).unwrap_err(),
            FlexError::Rejected { reason, .. } if reason == "CAPTURE_CONTEXT_EXPIRED"
        ));
        assert!(matches!(
            parse_tokenize_response(502, b"<html>bad gateway</html>").unwrap_err(),
            FlexError::Rejected { reason, status: 502, .. } if reason == "UNKNOWN"
        ));
    }
}

wasm_test! {
    fn card_data_debug_hides_the_card() {
        let debug = format!("{:?}", card());
        assert!(!debug.contains("4111") && !debug.contains("123"), "{debug}");
    }
}
