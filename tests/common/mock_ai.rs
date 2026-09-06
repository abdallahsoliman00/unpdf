//! A minimal synchronous mock HTTP server for the `ai` feature's integration tests.
//!
//! Mirrors `unparser-shared`'s own test helper of the same shape — hand-rolled on
//! `tiny_http` rather than a mocking framework, serving exactly the responses given,
//! one per request received, in order.
#![cfg(feature = "ai")]

use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

pub struct MockServer {
    url: String,
    handle: Option<JoinHandle<()>>,
    bodies: Arc<Mutex<Vec<String>>>,
    server: Arc<tiny_http::Server>,
}

impl MockServer {
    /// Starts a server that hands out `responses` (status code, body) in order, one
    /// per request received, then stops. Each request's body is recorded (see
    /// [`Self::received_bodies`]) before the response is sent.
    pub fn serving(responses: Vec<(u16, String)>) -> Self {
        let server = Arc::new(tiny_http::Server::http("127.0.0.1:0").expect("bind mock server"));
        let url = format!("http://{}", server.server_addr());
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let bodies_for_thread = Arc::clone(&bodies);
        let server_for_thread = Arc::clone(&server);
        let handle = std::thread::spawn(move || {
            for (status, body) in responses {
                // `unblock()` (called from Drop) makes this return an error, which is
                // how a test that deliberately expects *no* request still shuts down.
                let Ok(mut request) = server_for_thread.recv() else {
                    return;
                };
                let mut received = String::new();
                let _ = request.as_reader().read_to_string(&mut received);
                bodies_for_thread.lock().unwrap().push(received);

                let header =
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .expect("valid header");
                let response = tiny_http::Response::from_string(body)
                    .with_status_code(status)
                    .with_header(header);
                let _ = request.respond(response);
            }
        });
        Self {
            url,
            handle: Some(handle),
            bodies,
            server,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Request bodies received so far, in arrival order. Call after the caller
    /// under test has finished, or the list may still be filling in.
    pub fn received_bodies(&self) -> Vec<String> {
        self.bodies.lock().unwrap().clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        // Without this, a test that expects fewer requests than it queued responses
        // for (or none at all) would hang here forever: the server thread would still
        // be parked in `recv()`, and joining it would never return.
        self.server.unblock();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
