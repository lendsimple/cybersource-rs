//! Shared example setup: sandbox credentials from the environment, with
//! Cybersource's public `testrest` sample merchant as the default.

use cybersource::{Config, Credentials, Environment};

pub fn config() -> cybersource::Result<Config> {
    let var =
        |name: &str, default: &str| std::env::var(name).unwrap_or_else(|_| default.to_owned());
    Config::builder()
        .environment(Environment::Test)
        .merchant_id(var("CYBS_MERCHANT_ID", "testrest"))
        .credentials(Credentials::jwt_shared_secret(
            var("CYBS_KEY_ID", "08c94330-f618-42a3-b09d-e1e43be5efda"),
            &var(
                "CYBS_SHARED_SECRET",
                "yBJxy6LjM2TmcPGu+GaJrHtkke25fPpUX+UY6/L/1tE=",
            ),
        )?)
        .build()
}
