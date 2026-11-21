//! Walking every page of a list operation.
//!
//! ```ignore
//! let mut pages = client
//!     .tms()
//!     .get_customer_payment_instruments_list(customer_id)
//!     .limit(50)
//!     .pages();
//! while let Some(page) = pages.next().await {
//!     let page = page?;
//!     // ...
//! }
//! // Blocking clients: `for page in blocking.tms()....pages() { let page = page?; }`
//! ```

use crate::Result;
use crate::call::Call;
#[cfg(not(target_family = "wasm"))]
use crate::client::BlockingClient;
use crate::client::Client;
use crate::operation::Operation;
#[cfg(not(target_family = "wasm"))]
use crate::transport::BlockingHttpTransport;
use crate::transport::HttpTransport;

/// What one page of a list response says about the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageInfo {
    /// Items in this page.
    pub items: usize,
    /// Items in the whole list, when the response says.
    pub total: Option<i64>,
}

/// A list operation that pages with `offset` and `limit`. Implemented by
/// the generated operations listed under `[pagination]` in
/// `spec/codegen.toml`.
pub trait Paged: Operation {
    /// The requested offset.
    fn offset(&self) -> Option<i64>;
    /// The requested page size.
    fn limit(&self) -> Option<i64>;
    /// Moves to another offset.
    fn set_offset(&mut self, offset: i64);
    /// Reads the page size and total from a response.
    fn page_info(output: &Self::Output) -> PageInfo;
}

/// Iterates over the pages of a list operation; from [`Call::pages`].
#[derive(Debug)]
#[must_use = "a Pager does nothing until next() is called"]
pub struct Pager<'c, C, Op> {
    client: &'c C,
    op: Op,
    done: bool,
}

impl<'c, C, Op> Call<'c, C, Op>
where
    Op: Paged,
{
    /// Walks every page, starting at the call's offset (0 if unset).
    pub fn pages(self) -> Pager<'c, C, Op> {
        let client = self.client_ref();
        Pager {
            client,
            op: self.into_op(),
            done: false,
        }
    }
}

impl<C, Op: Paged> Pager<'_, C, Op> {
    /// Decides whether to fetch another page after `output`.
    fn advance(&mut self, output: &Op::Output) {
        let info = Op::page_info(output);
        let offset = self.op.offset().unwrap_or(0);
        let next = offset.saturating_add(i64::try_from(info.items).unwrap_or(i64::MAX));
        let short = self
            .op
            .limit()
            .is_some_and(|limit| i64::try_from(info.items).unwrap_or(i64::MAX) < limit);
        if info.items == 0 || short || info.total.is_some_and(|total| next >= total) {
            self.done = true;
        } else {
            self.op.set_offset(next);
        }
    }

    fn record(&mut self, result: Result<Op::Output>) -> Result<Op::Output> {
        match &result {
            Ok(output) => self.advance(output),
            Err(_) => self.done = true,
        }
        result
    }
}

impl<T: HttpTransport, Op: Paged> Pager<'_, Client<T>, Op> {
    /// The next page, or `None` after the last one (or after an error).
    pub async fn next(&mut self) -> Option<Result<Op::Output>> {
        if self.done {
            return None;
        }
        let result = self.client.execute(&self.op).await;
        Some(self.record(result))
    }
}

#[cfg(not(target_family = "wasm"))]
impl<T: BlockingHttpTransport, Op: Paged> Iterator for Pager<'_, BlockingClient<T>, Op> {
    type Item = Result<Op::Output>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let result = self.client.execute(&self.op);
        Some(self.record(result))
    }
}
