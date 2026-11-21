//! Status and reason codes from Cybersource responses (from the spec's
//! descriptions). All are open: unknown values are kept, not rejected.

crate::open_enum! {
    /// `status` of a payment (authorization or sale) or incremental authorization.
    pub enum PaymentStatus {
        Authorized = "AUTHORIZED",
        PartialAuthorized = "PARTIAL_AUTHORIZED",
        AuthorizedPendingReview = "AUTHORIZED_PENDING_REVIEW",
        AuthorizedRiskDeclined = "AUTHORIZED_RISK_DECLINED",
        PendingAuthentication = "PENDING_AUTHENTICATION",
        PendingReview = "PENDING_REVIEW",
        Declined = "DECLINED",
        InvalidRequest = "INVALID_REQUEST",
    }
}

crate::open_enum! {
    /// `status` of a capture.
    pub enum CaptureStatus {
        Pending = "PENDING",
        Transmitted = "TRANSMITTED",
    }
}

crate::open_enum! {
    /// `status` of a refund.
    pub enum RefundStatus {
        Pending = "PENDING",
        Declined = "DECLINED",
        InvalidRequest = "INVALID_REQUEST",
    }
}

crate::open_enum! {
    /// `status` of an authorization reversal.
    pub enum ReversalStatus {
        Reversed = "REVERSED",
    }
}

crate::open_enum! {
    /// `status` of a void.
    pub enum VoidStatus {
        Voided = "VOIDED",
        Cancelled = "CANCELLED",
        Failed = "FAILED",
    }
}

crate::open_enum! {
    /// `status` of a credit.
    pub enum CreditStatus {
        Pending = "PENDING",
        Authorized = "AUTHORIZED",
        Declined = "DECLINED",
        InvalidRequest = "INVALID_REQUEST",
        Completed = "COMPLETED",
    }
}

crate::open_enum! {
    /// `status` of a payout.
    pub enum PayoutStatus {
        Accepted = "ACCEPTED",
        Declined = "DECLINED",
        InvalidRequest = "INVALID_REQUEST",
    }
}

crate::open_enum! {
    /// `errorInformation.reason` of a declined or failed transaction, and
    /// `reason` of PTS error responses (HTTP 400/502).
    pub enum ReasonCode {
        AchVerificationFailed = "ACH_VERIFICATION_FAILED",
        AddressCountryWatchlistMatch = "ADDRESS_COUNTRY_WATCHLIST_MATCH",
        AllowablePinRetriesExceeded = "ALLOWABLE_PIN_RETRIES_EXCEEDED",
        AvsFailed = "AVS_FAILED",
        BlacklistedCustomer = "BLACKLISTED_CUSTOMER",
        BlockedByCardholder = "BLOCKED_BY_CARDHOLDER",
        ConsumerAuthenticationFailed = "CONSUMER_AUTHENTICATION_FAILED",
        ConsumerAuthenticationRequired = "CONSUMER_AUTHENTICATION_REQUIRED",
        ContactProcessor = "CONTACT_PROCESSOR",
        CustomerWatchlistMatch = "CUSTOMER_WATCHLIST_MATCH",
        CvnNotMatch = "CVN_NOT_MATCH",
        CvFailed = "CV_FAILED",
        DaggDenied = "DAGGDENIED",
        DaggRejected = "DAGGREJECTED",
        DecisionProfileReject = "DECISION_PROFILE_REJECT",
        DecisionProfileReview = "DECISION_PROFILE_REVIEW",
        DeclinedCheck = "DECLINED_CHECK",
        DsysRejected = "DSYSREJECTED",
        EmailCountryWatchlistMatch = "EMAIL_COUNTRY_WATCHLIST_MATCH",
        ExceedsCreditLimit = "EXCEEDS_CREDIT_LIMIT",
        ExpiredCard = "EXPIRED_CARD",
        GeneralDecline = "GENERAL_DECLINE",
        InsufficientFund = "INSUFFICIENT_FUND",
        InvalidAccount = "INVALID_ACCOUNT",
        InvalidCvn = "INVALID_CVN",
        InvalidMerchantConfiguration = "INVALID_MERCHANT_CONFIGURATION",
        IpCountryWatchlistMatch = "IP_COUNTRY_WATCHLIST_MATCH",
        IssuerUnavailable = "ISSUER_UNAVAILABLE",
        PaymentRefused = "PAYMENT_REFUSED",
        PendingAuthentication = "PENDING_AUTHENTICATION",
        ProcessorDeclined = "PROCESSOR_DECLINED",
        ProcessorError = "PROCESSOR_ERROR",
        ProcessorRiskControlDecline = "PROCESSOR_RISK_CONTROL_DECLINE",
        RiskControlDecline = "RISK_CONTROL_DECLINE",
        ScoreExceedsThreshold = "SCORE_EXCEEDS_THRESHOLD",
        StolenLostCard = "STOLEN_LOST_CARD",
        SuspendedAccount = "SUSPENDED_ACCOUNT",
        UnauthorizedCard = "UNAUTHORIZED_CARD",
        // PTS error responses.
        MissingField = "MISSING_FIELD",
        InvalidData = "INVALID_DATA",
        DuplicateRequest = "DUPLICATE_REQUEST",
        InvalidCard = "INVALID_CARD",
        SystemError = "SYSTEM_ERROR",
        ServerTimeout = "SERVER_TIMEOUT",
        ServiceTimeout = "SERVICE_TIMEOUT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trips<T>(known: &[&str])
    where
        T: for<'a> From<&'a str>
            + serde::Serialize
            + serde::de::DeserializeOwned
            + PartialEq
            + std::fmt::Debug,
        T: std::fmt::Display,
    {
        for value in known {
            let parsed = T::from(value);
            assert_eq!(parsed.to_string(), *value);
            let json = serde_json::to_string(&parsed).unwrap();
            assert_eq!(serde_json::from_str::<T>(&json).unwrap(), parsed);
        }
    }

    #[test]
    fn every_known_value_round_trips() {
        round_trips::<PaymentStatus>(PaymentStatus::KNOWN);
        round_trips::<CaptureStatus>(CaptureStatus::KNOWN);
        round_trips::<RefundStatus>(RefundStatus::KNOWN);
        round_trips::<ReversalStatus>(ReversalStatus::KNOWN);
        round_trips::<VoidStatus>(VoidStatus::KNOWN);
        round_trips::<CreditStatus>(CreditStatus::KNOWN);
        round_trips::<PayoutStatus>(PayoutStatus::KNOWN);
        round_trips::<ReasonCode>(ReasonCode::KNOWN);
        assert!(!PaymentStatus::from("AUTHORIZED").is_unknown());
    }

    proptest::proptest! {
        #[test]
        fn any_string_survives(s in ".*") {
            let status = PaymentStatus::from(s.as_str());
            proptest::prop_assert_eq!(status.as_str(), s.as_str());
            let json = serde_json::to_string(&status).unwrap();
            proptest::prop_assert_eq!(serde_json::from_str::<PaymentStatus>(&json).unwrap(), status);
        }
    }
}
