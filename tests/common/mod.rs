//! Shared test data.

#![allow(dead_code)]

use cybersource::models::CreatePaymentRequest;

/// A sandbox-ready authorization of `amount` USD on the Visa test card.
pub fn payment(code: &str, amount: &str) -> CreatePaymentRequest {
    cybersource::payment! {
        code: code,
        amount: (amount, "USD"),
        card: {
            number: "4111111111111111",
            expiration_month: "12",
            expiration_year: "2031",
            security_code: "123",
        },
        bill_to: {
            first_name: "John",
            last_name: "Doe",
            address1: "1 Market St",
            locality: "San Francisco",
            administrative_area: "CA",
            postal_code: "94105",
            country: "US",
            email: "test@cybs.com",
            phone_number: "4158880000",
        },
        capture: false,
        processing_information: { commerce_indicator: "internet" },
    }
}
