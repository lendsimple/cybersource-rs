use cybersource::{build, models::CreatePaymentRequest};

fn main() {
    let _ = build!(CreatePaymentRequest {
        client_reference_information: { cod: "x" },
    });
}
