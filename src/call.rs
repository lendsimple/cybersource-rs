//! [`Call`]: a pending API call returned by the generated accessors.
//!
//! ```ignore
//! // async: await the call directly (or use `.send()`)
//! let resp = client.payments().create_payment(req).await?;
//! // optional parameters are setters on the call
//! let page = client.tms().get_customer_payment_instruments(id).limit(50).await?;
//! // blocking
//! let resp = blocking.payments().create_payment(req).send()?;
//! ```

use std::future::IntoFuture;

use crate::Result;
#[cfg(not(target_family = "wasm"))]
use crate::client::BlockingClient;
use crate::client::Client;
use crate::operation::Operation;
use crate::response::Response;
#[cfg(not(target_family = "wasm"))]
use crate::transport::BlockingHttpTransport;
use crate::transport::{BoxFuture, HttpTransport, MaybeSend, MaybeSync};

/// An operation bound to a client, ready to send.
///
/// Set optional parameters with the generated setters, then `.await` it (async
/// client) or call [`send`](Call::send) (either client).
#[derive(Debug, Clone)]
#[must_use = "a Call does nothing until it is awaited or sent"]
pub struct Call<'c, C, Op> {
    client: &'c C,
    op: Op,
}

impl<'c, C, Op> Call<'c, C, Op> {
    /// Binds `op` to `client`.
    pub fn new(client: &'c C, op: Op) -> Self {
        Call { client, op }
    }

    /// The operation.
    pub fn op(&self) -> &Op {
        &self.op
    }

    /// The operation, mutably.
    pub fn op_mut(&mut self) -> &mut Op {
        &mut self.op
    }

    /// Unbinds the operation from the client.
    pub fn into_op(self) -> Op {
        self.op
    }

    /// Applies `f` to the operation; used by the generated setters.
    pub fn map_op(mut self, f: impl FnOnce(&mut Op)) -> Self {
        f(&mut self.op);
        self
    }
}

impl<T: HttpTransport, Op: Operation> Call<'_, Client<T>, Op> {
    /// Sends the call and returns the decoded body.
    pub async fn send(self) -> Result<Op::Output> {
        self.client.execute(&self.op).await
    }

    /// Sends the call and returns the body with status and headers.
    pub async fn send_with_response(self) -> Result<Response<Op::Output>> {
        self.client.execute_with_response(&self.op).await
    }
}

impl<'c, T, Op> IntoFuture for Call<'c, Client<T>, Op>
where
    T: HttpTransport + MaybeSync,
    Op: Operation + MaybeSend + MaybeSync + 'c,
    Op::Output: MaybeSend,
{
    type Output = Result<Op::Output>;
    type IntoFuture = BoxFuture<'c, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move { self.client.execute(&self.op).await })
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T: BlockingHttpTransport, Op: Operation> Call<'_, BlockingClient<T>, Op> {
    /// Sends the call and returns the decoded body.
    pub fn send(self) -> Result<Op::Output> {
        self.client.execute(&self.op)
    }

    /// Sends the call and returns the body with status and headers.
    pub fn send_with_response(self) -> Result<Response<Op::Output>> {
        self.client.execute_with_response(&self.op)
    }
}
