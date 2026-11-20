//! Payments models (hand-written subset; replaced by codegen in Stage 2).

use serde::{Deserialize, Serialize};

/// Body of `POST /pts/v2/payments` (authorization, or sale with `capture`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePaymentRequest {
    /// Merchant reference data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_reference_information: Option<ClientReferenceInformation>,
    /// How to process the payment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processing_information: Option<ProcessingInformation>,
    /// The payment method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_information: Option<PaymentInformation>,
    /// Amounts and billing details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order_information: Option<OrderInformation>,
}

/// Merchant reference data.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientReferenceInformation {
    /// Merchant-generated order reference. Cybersource uses it to detect duplicates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

/// How to process the payment.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessingInformation {
    /// `true` to authorize and capture in one request (a sale).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<bool>,
    /// Transaction type, e.g. `internet`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commerce_indicator: Option<String>,
}

/// The payment method.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentInformation {
    /// Card details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub card: Option<Card>,
}

/// Card details. `Debug` redacts the number and security code.
#[derive(Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Card {
    /// Primary account number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub number: Option<String>,
    /// Two-digit month, e.g. `12`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_month: Option<String>,
    /// Four-digit year, e.g. `2031`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_year: Option<String>,
    /// CVV/CVC.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_code: Option<String>,
}

impl std::fmt::Debug for Card {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redact = |v: &Option<String>| v.as_ref().map(|_| "[REDACTED]");
        f.debug_struct("Card")
            .field("number", &redact(&self.number))
            .field("expiration_month", &self.expiration_month)
            .field("expiration_year", &self.expiration_year)
            .field("security_code", &redact(&self.security_code))
            .finish()
    }
}

/// Amounts and billing details.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OrderInformation {
    /// Amount and currency.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub amount_details: Option<AmountDetails>,
    /// Billing address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bill_to: Option<BillTo>,
}

/// Amount and currency. Amounts are decimal strings, e.g. `"102.21"`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AmountDetails {
    /// Total amount as a decimal string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_amount: Option<String>,
    /// ISO 4217 currency code, e.g. `USD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}

/// Billing address.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BillTo {
    /// First name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    /// Last name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Street address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address1: Option<String>,
    /// City.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// State or province.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub administrative_area: Option<String>,
    /// Postal code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// ISO 3166-1 alpha-2 country code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// Email address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// Phone number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
}

/// Response to `POST /pts/v2/payments`, sent with HTTP 201.
///
/// A 201 does **not** mean approved: check [`status`](Self::status). Declines
/// and risk rejections also arrive as 201 (e.g. `DECLINED`,
/// `AUTHORIZED_PENDING_REVIEW`, `AUTHORIZED_RISK_DECLINED`).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PtsV2PaymentsPost201Response {
    /// HAL links (self, capture, reversal, ...).
    #[serde(rename = "_links", skip_serializing_if = "Option::is_none")]
    pub links: Option<serde_json::Value>,
    /// The request id; use it for follow-on operations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// When Cybersource processed the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submit_time_utc: Option<String>,
    /// e.g. `AUTHORIZED`, `PARTIAL_AUTHORIZED`, `DECLINED`, `PENDING_REVIEW`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Reconciliation id for settlement reports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reconciliation_id: Option<String>,
    /// Why the payment was not approved, when it wasn't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_information: Option<ErrorInformation>,
    /// Processor results.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processor_information: Option<ProcessorInformation>,
}

/// Reason a payment was not approved.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorInformation {
    /// e.g. `PROCESSOR_DECLINED`, `INSUFFICIENT_FUND`, `AVS_FAILED`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Human-readable description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Processor results.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessorInformation {
    /// Authorization code from the issuer.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_code: Option<String>,
    /// Processor response code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    /// Network transaction id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_id: Option<String>,
}
