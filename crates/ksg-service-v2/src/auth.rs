//! The holder's signature on a request to the service (`crate::server`):
//! the message and the headers, for the server and for its clients alike.

use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Ed25519Signer;

/// How far a holder's clock may stand from the service's: five minutes.
pub const AUTH_WINDOW_MS: u64 = 5 * 60 * 1000;

/// The message a holder signs over a request:
/// `ksg:service:v1 \n METHOD \n PATH \n TIME \n SHA-256(body)`.
#[must_use]
pub fn auth_message(method: &str, path: &str, time_ms: u64, body: &[u8]) -> Vec<u8> {
    format!(
        "ksg:service:v1\n{method}\n{path}\n{time_ms}\n{}",
        Hash::sha256(body).to_multihash()
    )
    .into_bytes()
}

/// The three headers of a request signed by a holder: name, value pairs.
#[must_use]
pub fn sign_request(
    signer: &Ed25519Signer,
    holder: &str,
    method: &str,
    path: &str,
    time_ms: u64,
    body: &[u8],
) -> [(&'static str, String); 3] {
    let sig = signer.sign(&auth_message(method, path, time_ms, body));
    [
        ("x-ksg-holder", holder.to_owned()),
        ("x-ksg-time", time_ms.to_string()),
        ("x-ksg-signature", sig.value),
    ]
}
