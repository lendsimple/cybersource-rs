//! The request DSL: `build!`, `patch!` and the flow macros.

#![cfg(feature = "payments")]

use cybersource::models::{
    CreatePaymentRequest, Ptsv2paymentsClientReferenceInformation,
    Ptsv2paymentsMerchantDefinedInformation, Ptsv2paymentsOrderInformation,
    Ptsv2paymentsOrderInformationAmountDetails, Ptsv2paymentsOrderInformationLineItems,
    Ptsv2paymentsPaymentInformation, Ptsv2paymentsPaymentInformationCard,
    Ptsv2paymentsProcessingInformation,
};
use cybersource::{amount, build, capture, patch, payment, refund, reversal, void};
use serde_json::{Value, json};

fn json_of<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn build_equals_the_hand_written_struct() {
    let pan = String::from("4111111111111111");
    let built = build!(CreatePaymentRequest {
        client_reference_information: { code: "TC50171_3" },
        processing_information: { capture: true },
        payment_information: {
            card: { number: pan.clone(), expiration_month: "12", expiration_year: "2031" },
        },
        order_information: {
            amount_details: { total_amount: amount!("102.21"), currency: "USD" },
        },
    });

    let by_hand = CreatePaymentRequest {
        client_reference_information: Some(Ptsv2paymentsClientReferenceInformation {
            code: Some("TC50171_3".into()),
            ..Default::default()
        }),
        processing_information: Some(Ptsv2paymentsProcessingInformation {
            capture: Some(true),
            ..Default::default()
        }),
        payment_information: Some(Ptsv2paymentsPaymentInformation {
            card: Some(Ptsv2paymentsPaymentInformationCard {
                number: Some(pan),
                expiration_month: Some("12".into()),
                expiration_year: Some("2031".into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        order_information: Some(Ptsv2paymentsOrderInformation {
            amount_details: Some(Ptsv2paymentsOrderInformationAmountDetails {
                total_amount: Some("102.21".into()),
                currency: Some("USD".into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };
    assert_eq!(built, by_hand);
}

#[test]
fn lists_of_objects_and_of_values() {
    let req = build!(CreatePaymentRequest {
        order_information: {
            line_items: [
                { product_name: "Widget", unit_price: "51.10", quantity: 2 },
                { product_name: "Gadget", unit_price: "1.00" },
            ],
        },
        processing_information: { action_list: ["DECISION_SKIP", "TOKEN_CREATE"] },
    });
    let j = json_of(&req);
    assert_eq!(j["orderInformation"]["lineItems"][0]["quantity"], 2);
    assert_eq!(
        j["orderInformation"]["lineItems"][1]["productName"],
        "Gadget"
    );
    assert_eq!(
        j["processingInformation"]["actionList"],
        json!(["DECISION_SKIP", "TOKEN_CREATE"])
    );
}

#[test]
fn raw_assignment_and_raw_identifiers() {
    let mdi = vec![Ptsv2paymentsMerchantDefinedInformation {
        key: Some("1".into()),
        value: Some("x".into()),
    }];
    let req = build!(CreatePaymentRequest {
        merchant_defined_information = Some(mdi.clone()),
        payment_information: { card: { r#type: "001" } },
    });
    assert_eq!(req.merchant_defined_information, Some(mdi));
    assert_eq!(json_of(&req)["paymentInformation"]["card"]["type"], "001");
}

#[test]
fn base_value_and_patch() {
    let base = build!(CreatePaymentRequest {
        client_reference_information: { code: "a" },
        order_information: { amount_details: { total_amount: "1.00", currency: "USD" } },
    });
    let mut req = build!(CreatePaymentRequest {
        ..base.clone(),
        order_information: { amount_details: { total_amount: "2.00" } },
    });
    assert_eq!(
        json_of(&req)["orderInformation"]["amountDetails"],
        json!({"totalAmount": "2.00", "currency": "USD"})
    );
    assert_eq!(
        req.client_reference_information,
        base.client_reference_information
    );

    patch!(req, { processing_information: { capture: false } });
    assert_eq!(req.processing_information.unwrap().capture, Some(false));
}

#[test]
fn payment_shorthands_and_passthrough_fields() {
    let total = String::from("5.00");
    let req = payment! {
        code: "order-42",
        amount: "100.00" USD,
        card: { number: "4111111111111111", expiration_month: "12", expiration_year: "2031" },
        bill_to: { first_name: "Jane", country: "US" },
        ship_to: { locality: "Austin" },
        capture: true,
        device_information: { ip_address: "192.0.2.1" },
        order_information: {
            line_items: [ { product_name: "Widget", unit_price: "100.00" } ],
        },
    };
    let j = json_of(&req);
    assert_eq!(j["clientReferenceInformation"]["code"], "order-42");
    assert_eq!(
        j["orderInformation"]["amountDetails"],
        json!({"totalAmount": "100.00", "currency": "USD"})
    );
    assert_eq!(j["orderInformation"]["billTo"]["firstName"], "Jane");
    assert_eq!(j["orderInformation"]["shipTo"]["locality"], "Austin");
    assert_eq!(
        j["orderInformation"]["lineItems"][0]["productName"],
        "Widget"
    );
    assert_eq!(j["processingInformation"]["capture"], true);
    assert_eq!(j["deviceInformation"]["ipAddress"], "192.0.2.1");

    let runtime = payment! { amount: (total, "eur") };
    assert_eq!(
        json_of(&runtime)["orderInformation"]["amountDetails"]["totalAmount"],
        "5.00"
    );
}

#[test]
fn follow_on_flow_macros() {
    let c = capture! { code: "cap-1", amount: "10.00" USD };
    assert_eq!(
        json_of(&c)["orderInformation"]["amountDetails"]["totalAmount"],
        "10.00"
    );
    let r = refund! { amount: "2.50" USD };
    assert_eq!(
        json_of(&r)["orderInformation"]["amountDetails"]["currency"],
        "USD"
    );
    let rev = reversal! { code: "rev-1", amount: "10.00" USD, reversal_information: { reason: "testing" } };
    let j = json_of(&rev);
    assert_eq!(
        j["reversalInformation"]["amountDetails"]["totalAmount"],
        "10.00"
    );
    assert_eq!(j["reversalInformation"]["reason"], "testing");
    let v = void! { code: "void-1" };
    assert_eq!(json_of(&v)["clientReferenceInformation"]["code"], "void-1");
}

#[test]
fn large_requests_fit_the_default_recursion_limit() {
    let req = build!(CreatePaymentRequest {
        client_reference_information: { code: "c", transaction_id: "t", comments: "x", application_name: "app" },
        processing_information: { capture: true, commerce_indicator: "internet", payment_solution: "x", reconciliation_id: "r", link_id: "l", report_group: "g", visa_checkout_id: "v", purchase_level: "1" },
        order_information: {
            amount_details: { total_amount: "1.00", currency: "USD", discount_amount: "0", duty_amount: "0", gratuity_amount: "0", tax_amount: "0", national_tax_included: "0", tax_applied_after_discount: "0", tax_applied_level: "0", tax_type_code: "0", freight_amount: "0", foreign_amount: "0", foreign_currency: "EUR", exchange_rate: "1" },
            bill_to: { first_name: "a", last_name: "b", middle_name: "c", company: { name: "d" }, address1: "e", address2: "f", locality: "g", administrative_area: "h", postal_code: "i", country: "US", email: "j@k.example", phone_number: "1" },
            ship_to: { first_name: "a", last_name: "b", address1: "e", locality: "g", administrative_area: "h", postal_code: "i", country: "US" },
            line_items: [ { product_name: "a" }, { product_name: "b" }, { product_name: "c" }, { product_name: "d" } ],
        },
    });
    assert_eq!(req.order_information.unwrap().line_items.unwrap().len(), 4);
    let _ = Ptsv2paymentsOrderInformationLineItems::default();
}
