//! Payments operations (hand-written subset; replaced by codegen in Stage 2).

use std::borrow::Cow;

use bytes::Bytes;
use http::{Method, StatusCode};

use crate::Result;
#[cfg(not(target_family = "wasm"))]
use crate::client::BlockingClient;
use crate::client::Client;
use crate::models::{CreatePaymentRequest, PtsV2PaymentsPost201Response};
use crate::operation::{Operation, OperationMeta, json_body, json_decode};
#[cfg(not(target_family = "wasm"))]
use crate::transport::BlockingHttpTransport;
use crate::transport::HttpTransport;

/// `POST /pts/v2/payments`: authorize a payment, or authorize and capture
/// it (a sale) when `processingInformation.capture` is true.
#[derive(Debug, Clone, Copy)]
pub struct CreatePayment<'a> {
    /// The request body.
    pub body: &'a CreatePaymentRequest,
}

static CREATE_PAYMENT: OperationMeta =
    OperationMeta::new("createPayment", Method::POST, "/pts/v2/payments").moves_money();

impl Operation for CreatePayment<'_> {
    type Output = PtsV2PaymentsPost201Response;

    fn meta(&self) -> &'static OperationMeta {
        &CREATE_PAYMENT
    }

    fn path(&self) -> Cow<'_, str> {
        Cow::Borrowed("/pts/v2/payments")
    }

    fn body(&self) -> Result<Option<Bytes>> {
        json_body(self.body)
    }

    fn decode(&self, _status: StatusCode, body: &Bytes) -> Result<Self::Output> {
        json_decode(body)
    }
}

/// The Payments API, from [`Client::payments`] or [`BlockingClient::payments`].
#[derive(Debug, Clone, Copy)]
pub struct Payments<'c, C> {
    client: &'c C,
}

impl<T: HttpTransport> Client<T> {
    /// The Payments API.
    pub fn payments(&self) -> Payments<'_, Self> {
        Payments { client: self }
    }
}

impl<T: HttpTransport> Payments<'_, Client<T>> {
    /// Authorizes a payment (or makes a sale when `capture` is set).
    ///
    /// Returns `Ok` for every HTTP 201, including declines: check `status`.
    pub async fn create_payment(
        &self,
        body: &CreatePaymentRequest,
    ) -> Result<PtsV2PaymentsPost201Response> {
        self.client.execute(&CreatePayment { body }).await
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T: BlockingHttpTransport> BlockingClient<T> {
    /// The Payments API.
    pub fn payments(&self) -> Payments<'_, Self> {
        Payments { client: self }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T: BlockingHttpTransport> Payments<'_, BlockingClient<T>> {
    /// Authorizes a payment (or makes a sale when `capture` is set).
    ///
    /// Returns `Ok` for every HTTP 201, including declines: check `status`.
    pub fn create_payment(
        &self,
        body: &CreatePaymentRequest,
    ) -> Result<PtsV2PaymentsPost201Response> {
        self.client.execute(&CreatePayment { body })
    }
}
