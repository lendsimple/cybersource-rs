//! Typed statuses on payment responses, and [`PaymentOutcome`].
//!
//! Cybersource answers declines with HTTP 201, so whether a payment
//! succeeded is in the body's `status`, not the HTTP status.

#[allow(unused_imports)]
use crate::models;
#[allow(unused_imports)]
use crate::types::status::*;

/// `fn <method>(&self) -> Option<Enum>` reading `status`.
macro_rules! status_getter {
    ($feature:literal: $($model:ident => $method:ident: $enum:ident),* $(,)?) => {
        $(
            #[cfg(feature = $feature)]
            impl models::$model {
                /// The `status` as a typed (open) enum.
                pub fn $method(&self) -> Option<$enum> {
                    self.status.as_deref().map($enum::from)
                }
            }
        )*
    };
}

/// `fn reason(&self) -> Option<ReasonCode>` reading `errorInformation.reason`.
macro_rules! reason_getter {
    ($feature:literal: $($model:ident),* $(,)?) => {
        $(
            #[cfg(feature = $feature)]
            impl models::$model {
                /// Why the transaction was not approved, as a typed (open) enum.
                pub fn reason(&self) -> Option<ReasonCode> {
                    self.error_information.as_ref()?.reason.as_deref().map(ReasonCode::from)
                }
            }
        )*
    };
}

status_getter!("payments":
    PtsV2PaymentsPost201Response => payment_status: PaymentStatus,
    PtsV2IncrementalAuthorizationPatch201Response => payment_status: PaymentStatus,
    PtsV2PaymentsCapturesPost201Response => capture_status: CaptureStatus,
    PtsV2PaymentsRefundPost201Response => refund_status: RefundStatus,
    PtsV2CapturesRefundsPost201Response => refund_status: RefundStatus,
    PtsV2PaymentsReversalsPost201Response => reversal_status: ReversalStatus,
    PtsV2ReversalsPost201Response => reversal_status: ReversalStatus,
    PtsV2PaymentsVoidsPost201Response => void_status: VoidStatus,
    PtsV2CapturesVoidsPost201Response => void_status: VoidStatus,
    PtsV2RefundsVoidsPost201Response => void_status: VoidStatus,
    PtsV2CreditsVoidsPost201Response => void_status: VoidStatus,
    PtsV2VoidsPost200Response => void_status: VoidStatus,
    PtsV2CreditsPost201Response => credit_status: CreditStatus,
);
status_getter!("payouts": PtsV2PayoutsPost201Response => payout_status: PayoutStatus);

reason_getter!("payments":
    PtsV2PaymentsPost201Response,
    PtsV2IncrementalAuthorizationPatch201Response,
    PtsV2PaymentsRefundPost201Response,
    PtsV2CapturesRefundsPost201Response,
    PtsV2CreditsPost201Response,
);
reason_getter!("payouts": PtsV2PayoutsPost201Response);

/// The result of an authorization or sale, interpreted.
#[cfg(feature = "payments")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentOutcome {
    /// The payment status, if present.
    pub status: Option<PaymentStatus>,
    /// Why it was not approved, if it wasn't.
    pub reason: Option<ReasonCode>,
    /// Cybersource's message, if any.
    pub message: Option<String>,
}

#[cfg(feature = "payments")]
impl From<&models::PtsV2PaymentsPost201Response> for PaymentOutcome {
    fn from(resp: &models::PtsV2PaymentsPost201Response) -> Self {
        PaymentOutcome {
            status: resp.payment_status(),
            reason: resp.reason(),
            message: resp
                .error_information
                .as_ref()
                .and_then(|e| e.message.clone()),
        }
    }
}

#[cfg(feature = "payments")]
impl PaymentOutcome {
    /// Authorized in full or in part. A partial authorization covers less
    /// than the requested amount: check [`is_partial`](Self::is_partial).
    pub fn is_approved(&self) -> bool {
        matches!(
            self.status,
            Some(PaymentStatus::Authorized | PaymentStatus::PartialAuthorized)
        )
    }

    /// Authorized for less than the requested amount.
    pub fn is_partial(&self) -> bool {
        self.status == Some(PaymentStatus::PartialAuthorized)
    }

    /// Held for review or waiting for payer authentication (3-D Secure).
    pub fn needs_review(&self) -> bool {
        matches!(
            self.status,
            Some(
                PaymentStatus::AuthorizedPendingReview
                    | PaymentStatus::PendingReview
                    | PaymentStatus::PendingAuthentication
            )
        )
    }

    /// Declined, rejected by risk screening, or invalid.
    pub fn is_declined(&self) -> bool {
        matches!(
            self.status,
            Some(
                PaymentStatus::Declined
                    | PaymentStatus::AuthorizedRiskDeclined
                    | PaymentStatus::InvalidRequest
            )
        )
    }
}

#[cfg(all(test, feature = "payments"))]
mod tests {
    use super::*;

    fn outcome(status: &str, reason: Option<&str>) -> PaymentOutcome {
        let resp: models::PtsV2PaymentsPost201Response =
            serde_json::from_value(serde_json::json!({
                "status": status,
                "errorInformation": { "reason": reason, "message": "m" }
            }))
            .unwrap();
        PaymentOutcome::from(&resp)
    }

    #[test]
    fn classifies_every_status() {
        let table = [
            ("AUTHORIZED", true, false, false),
            ("PARTIAL_AUTHORIZED", true, false, false),
            ("AUTHORIZED_PENDING_REVIEW", false, true, false),
            ("PENDING_REVIEW", false, true, false),
            ("PENDING_AUTHENTICATION", false, true, false),
            ("AUTHORIZED_RISK_DECLINED", false, false, true),
            ("DECLINED", false, false, true),
            ("INVALID_REQUEST", false, false, true),
            ("SOMETHING_NEW", false, false, false),
        ];
        for (status, approved, review, declined) in table {
            let o = outcome(status, None);
            assert_eq!(
                (o.is_approved(), o.needs_review(), o.is_declined()),
                (approved, review, declined),
                "{status}"
            );
        }
        assert!(outcome("PARTIAL_AUTHORIZED", None).is_partial());
    }

    #[test]
    fn reason_and_message_are_typed() {
        let o = outcome("DECLINED", Some("INSUFFICIENT_FUND"));
        assert_eq!(o.reason, Some(ReasonCode::InsufficientFund));
        assert_eq!(o.message.as_deref(), Some("m"));
        assert_eq!(
            outcome("DECLINED", Some("NEW_CODE")).reason,
            Some(ReasonCode::Unknown("NEW_CODE".into()))
        );
    }
}
