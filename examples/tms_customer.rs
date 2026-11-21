//! Token Management: create a customer, update it safely with its ETag,
//! list its payment instruments page by page, then delete it.
//!
//! `cargo run --example tms_customer`

#[path = "common/mod.rs"]
mod common;

use cybersource::{Client, build, models};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new(common::config()?);
    let tms = client.tms();

    let created = tms
        .post_customer(build!(models::PostCustomerRequest {
            buyer_information: { merchant_customer_id: "example-customer", email: "test@cybs.com" },
            client_reference_information: { code: "example-tms" },
        }))
        .await?;
    let id = created.id.clone().expect("a created customer has an id");
    println!("created customer {id}");

    // Read with its ETag, then update only if nobody changed it meanwhile.
    let current = tms.get_customer(id.clone()).send_with_response().await?;
    if let Some(etag) = current.etag() {
        tms.patch_customer(
            id.clone(),
            build!(models::PatchCustomerRequest { buyer_information: { email: "new@cybs.com" } }),
        )
        .if_match(etag)
        .await?;
        println!("updated with if-match {etag}");
    }

    let mut pages = tms
        .get_customer_payment_instruments_list(id.clone())
        .limit(10)
        .pages();
    while let Some(page) = pages.next().await {
        let page = page?;
        println!("page: {:?} of {:?} instruments", page.count, page.total);
    }

    tms.delete_customer(id).await?;
    println!("deleted");
    Ok(())
}
