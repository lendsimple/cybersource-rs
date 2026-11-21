//! Which operations get message-level encryption.

use super::MleConfig;
use crate::operation::{MlePolicy, OperationMeta};

/// Whether to encrypt the request and ask for an encrypted response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decision {
    /// Encrypt the request body.
    pub request: bool,
    /// Ask for an encrypted response.
    pub response: bool,
}

/// Applies the policy, as the official SDKs do: a per-operation override
/// wins; otherwise mandatory requests are encrypted unless disabled, optional
/// ones only when enabled globally; responses follow the global flag, and
/// mandatory ones are always requested.
pub fn resolve(meta: &OperationMeta, mle: &MleConfig) -> Decision {
    let rule = mle.overrides.get(meta.id).copied().unwrap_or_default();
    let request = rule.request.unwrap_or(match meta.mle_request {
        MlePolicy::Mandatory => !mle.disable_mandatory,
        MlePolicy::Optional => mle.optional_globally,
        _ => false,
    });
    let response = rule.response.unwrap_or(match meta.mle_response {
        MlePolicy::Mandatory => true,
        _ => mle.response_globally,
    });
    Decision { request, response }
}

#[cfg(test)]
mod tests {
    use http::Method;

    use super::*;
    use crate::mle::MleOverride;
    use crate::operation::MlePolicy::{Mandatory, Never, Optional};

    fn meta(request: MlePolicy, response: MlePolicy) -> OperationMeta {
        OperationMeta::new("op", Method::POST, "/op").mle(request, response)
    }

    fn decide(request: MlePolicy, response: MlePolicy, mle: &MleConfig) -> (bool, bool) {
        let d = resolve(&meta(request, response), mle);
        (d.request, d.response)
    }

    #[test]
    fn defaults_encrypt_only_mandatory_requests() {
        let mle = MleConfig::new();
        assert_eq!(decide(Mandatory, Never, &mle), (true, false));
        assert_eq!(decide(Optional, Optional, &mle), (false, false));
        assert_eq!(decide(Never, Never, &mle), (false, false));
        assert_eq!(decide(Never, Mandatory, &mle), (false, true));
    }

    #[test]
    fn global_flags() {
        let mle = MleConfig::new()
            .optional_globally(true)
            .response_globally(true);
        assert_eq!(decide(Optional, Optional, &mle), (true, true));
        assert_eq!(decide(Never, Never, &mle), (false, true));
        let off = MleConfig::new().disable_mandatory(true);
        assert_eq!(decide(Mandatory, Never, &off), (false, false));
    }

    #[test]
    fn overrides_win_in_both_directions() {
        let on = MleConfig::new().override_op(
            "op",
            MleOverride {
                request: Some(true),
                response: Some(true),
            },
        );
        assert_eq!(decide(Never, Never, &on), (true, true));
        let off = MleConfig::new()
            .optional_globally(true)
            .response_globally(true)
            .override_op(
                "op",
                MleOverride {
                    request: Some(false),
                    response: Some(false),
                },
            );
        assert_eq!(decide(Mandatory, Mandatory, &off), (false, false));
        let partial = MleConfig::new().optional_globally(true).override_op(
            "op",
            MleOverride {
                request: None,
                response: Some(true),
            },
        );
        assert_eq!(decide(Optional, Never, &partial), (true, true));
    }

    #[test]
    fn overrides_apply_only_to_their_operation() {
        let mle = MleConfig::new().override_op(
            "other",
            MleOverride {
                request: Some(true),
                response: None,
            },
        );
        assert_eq!(decide(Optional, Never, &mle), (false, false));
    }
}
