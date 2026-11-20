//! Shared test data.

#![allow(dead_code)]

use cybersource::models::{
    CreatePaymentRequest, Ptsv2paymentsClientReferenceInformation, Ptsv2paymentsOrderInformation,
    Ptsv2paymentsOrderInformationAmountDetails, Ptsv2paymentsOrderInformationBillTo,
    Ptsv2paymentsPaymentInformation, Ptsv2paymentsPaymentInformationCard,
    Ptsv2paymentsProcessingInformation,
};

/// A sandbox-ready authorization of `amount` USD on the Visa test card.
pub fn payment(code: &str, amount: &str) -> CreatePaymentRequest {
    CreatePaymentRequest {
        client_reference_information: Some(Ptsv2paymentsClientReferenceInformation {
            code: Some(code.into()),
            ..Default::default()
        }),
        processing_information: Some(Ptsv2paymentsProcessingInformation {
            capture: Some(false),
            commerce_indicator: Some("internet".into()),
            ..Default::default()
        }),
        payment_information: Some(Ptsv2paymentsPaymentInformation {
            card: Some(Ptsv2paymentsPaymentInformationCard {
                number: Some("4111111111111111".into()),
                expiration_month: Some("12".into()),
                expiration_year: Some("2031".into()),
                security_code: Some("123".into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        order_information: Some(Ptsv2paymentsOrderInformation {
            amount_details: Some(Ptsv2paymentsOrderInformationAmountDetails {
                total_amount: Some(amount.into()),
                currency: Some("USD".into()),
                ..Default::default()
            }),
            bill_to: Some(Ptsv2paymentsOrderInformationBillTo {
                first_name: Some("John".into()),
                last_name: Some("Doe".into()),
                address1: Some("1 Market St".into()),
                locality: Some("San Francisco".into()),
                administrative_area: Some("CA".into()),
                postal_code: Some("94105".into()),
                country: Some("US".into()),
                email: Some("test@cybs.com".into()),
                phone_number: Some("4158880000".into()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}
