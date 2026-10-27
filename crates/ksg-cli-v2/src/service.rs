//! The reader as a client of the service (`ksg-service`, `ksg_service_v2::server`).
//!
//! | Command | Who | What |
//! |---|---|---|
//! | `service-register` | an owner-watcher | presents its container's channel bundle and status section: path A's registration |
//! | `service-look` | an owner-watcher | asks whose an anchor is: a challenge, then the request signed with the owner key |
//! | `service-views` | a holder | takes the notices "who looked" waiting for its container and records them |
//!
//! The owner key of the home directory signs both as the owner-watcher and
//! as the holder: in the chain it is the packet's holder key, and the
//! service knows a holder by the same key.

use std::time::Duration;

use serde_json::Value;

use ksg_core_v2::crypto::sign::Ed25519Signer;
use ksg_service_v2::auth::sign_request;

/// The service at one address.
pub struct Service {
    url: String,
    agent: ureq::Agent,
}

fn answer(r: Result<ureq::Response, ureq::Error>, what: &str) -> Result<Value, String> {
    match r {
        Ok(resp) => resp.into_json().map_err(|e| format!("{what}: {e}")),
        Err(ureq::Error::Status(code, resp)) => {
            let body: Value = resp.into_json().unwrap_or(Value::Null);
            Err(format!(
                "{what}: the service answered {code}: {}",
                body.get("error")
                    .and_then(Value::as_str)
                    .unwrap_or("no reason given")
            ))
        }
        Err(e) => Err(format!("{what}: {e}")),
    }
}

impl Service {
    /// The service at `url` (`http://HOST:PORT` or `https://…`).
    #[must_use]
    pub fn new(url: &str) -> Self {
        Self {
            url: url.trim_end_matches('/').to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(30))
                .build(),
        }
    }

    /// `GET path`.
    ///
    /// # Errors
    ///
    /// The service did not answer, or answered with an error.
    pub fn get(&self, path: &str) -> Result<Value, String> {
        answer(self.agent.get(&format!("{}{path}", self.url)).call(), path)
    }

    /// `GET path`, signed by a holder.
    ///
    /// # Errors
    ///
    /// The service did not answer, or answered with an error.
    pub fn get_signed(
        &self,
        path: &str,
        signer: &Ed25519Signer,
        holder: &str,
    ) -> Result<Value, String> {
        let mut rq = self.agent.get(&format!("{}{path}", self.url));
        for (k, v) in sign_request(signer, holder, "GET", path, crate::clock::now_ms(), &[]) {
            rq = rq.set(k, &v);
        }
        answer(rq.call(), path)
    }

    /// `POST path` with a JSON body, signed by a holder when `signed` is given.
    ///
    /// # Errors
    ///
    /// The service did not answer, or answered with an error.
    pub fn post(
        &self,
        path: &str,
        body: &Value,
        signed: Option<(&Ed25519Signer, &str)>,
    ) -> Result<Value, String> {
        let bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;
        let mut rq = self
            .agent
            .post(&format!("{}{path}", self.url))
            .set("content-type", "application/json");
        if let Some((signer, holder)) = signed {
            for (k, v) in sign_request(signer, holder, "POST", path, crate::clock::now_ms(), &bytes)
            {
                rq = rq.set(k, &v);
            }
        }
        answer(rq.send_bytes(&bytes), path)
    }
}
