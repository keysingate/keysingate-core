//! The issuer's till: x402, seller's side (Goal 2, criterion G2-8;
//! `[decision]` 06.10 — a repeated `bare` is paid, $0.1–1, to the issuer's own
//! crypto account; on the stand — no real money, `[decision]` 09.10).
//!
//! | Step | Who | Here |
//! |---|---|---|
//! | 1. "pay first" — HTTP 402 with what is asked | issuer | [`payment_required`] |
//! | 2. the payer signs an EIP-3009 `TransferWithAuthorization` for USDC and sends it in `X-PAYMENT` | payer (μ Gate, a wallet) | — |
//! | 3. the payment is checked **before** the `bare` is handed over | issuer | [`accept`] |
//! | 4. settlement: the authorization is submitted on chain | facilitator | not here — see below |
//!
//! [`accept`] checks everything that can be checked without the chain: the
//! scheme, the network, the token, the recipient, the amount, the time window,
//! the signature (EIP-712, secp256k1, low-s only) against the payer's address,
//! and that this authorization was not taken before. What needs the chain —
//! the payer's balance, a nonce already used on chain, the transfer itself —
//! is the settlement step, which the stand does not take (no real money).

use std::collections::BTreeSet;

use base64::Engine as _;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest as _, Keccak256};

/// The only x402 version and scheme taken.
pub const X402_VERSION: u64 = 1;
/// "exact": the payer authorizes exactly one transfer of a known amount.
pub const SCHEME: &str = "exact";
const TWA_TYPE: &[u8] = b"TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)";
const DOMAIN_TYPE: &[u8] =
    b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";

/// An EVM address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// From `0x` and 40 hex digits, any case (the mixed-case checksum is not
    /// required: the bytes are what is compared).
    ///
    /// # Errors
    ///
    /// Not that.
    pub fn parse(s: &str) -> Result<Self, String> {
        let h = s
            .strip_prefix("0x")
            .ok_or_else(|| format!("address {s:?}: no 0x"))?;
        let b = hex::decode(h).map_err(|_| format!("address {s:?}: not hex"))?;
        Ok(Self(
            b.try_into()
                .map_err(|_| format!("address {s:?}: not 20 bytes"))?,
        ))
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

/// The issuer's till: where it is paid and in what.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Till {
    /// x402 network name, e.g. `base-sepolia`.
    pub network: String,
    /// Its EVM chain id, e.g. 84532.
    pub chain_id: u64,
    /// The token contract (USDC).
    pub asset: Address,
    /// The token's EIP-712 domain name (`USDC` on Base Sepolia).
    pub asset_name: String,
    /// The token's EIP-712 domain version (`2`).
    pub asset_version: String,
    /// The issuer's account.
    pub pay_to: Address,
    /// How long the issuer waits for a payment, seconds.
    pub max_timeout_seconds: u64,
}

impl Till {
    /// USDC on Base Sepolia — the test network; no real money.
    #[must_use]
    pub fn base_sepolia(pay_to: Address) -> Self {
        Self {
            network: "base-sepolia".into(),
            chain_id: 84_532,
            asset: Address(
                hex::decode("036CbD53842c5426634e7929541eC2318f3dCF7e")
                    .expect("constant")
                    .try_into()
                    .expect("constant"),
            ),
            asset_name: "USDC".into(),
            asset_version: "2".into(),
            pay_to,
            max_timeout_seconds: 300,
        }
    }

    fn domain_separator(&self) -> [u8; 32] {
        let mut chain = [0u8; 32];
        chain[24..].copy_from_slice(&self.chain_id.to_be_bytes());
        keccak(&[
            &keccak(&[DOMAIN_TYPE]),
            &keccak(&[self.asset_name.as_bytes()]),
            &keccak(&[self.asset_version.as_bytes()]),
            &chain,
            &word_addr(&self.asset),
        ])
    }
}

/// What is sold: one paid `bare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Price {
    /// In the token's minor units (USDC: 6 decimals; $0.10 = 100 000).
    pub minor: u128,
    /// The URL the payer asked for.
    pub resource: String,
    /// What it is, for the payer's wallet.
    pub description: String,
}

/// The floor of a freeze or a succession: $10 in USDC minor units.
pub const FREEZE_FLOOR_MINOR: u128 = 10_000_000;

/// The price of E-14 (succession on a lost owner's key) and E-23 (freeze on
/// the owner's application): ten times what the container cost, and never
/// less than $10 (KS-8 E-14 `[decision]` 10.09, E-23 `[decision]` 11.09 "as
/// E-14"). `container_minor` is the container's price in the same minor
/// units; a free container (`bare`) still pays the floor.
#[must_use]
pub fn freeze_price_minor(container_minor: u128) -> u128 {
    container_minor.saturating_mul(10).max(FREEZE_FLOOR_MINOR)
}

/// The 402 answer's body (x402 version 1).
#[must_use]
pub fn payment_required(till: &Till, price: &Price) -> serde_json::Value {
    serde_json::json!({
        "x402Version": X402_VERSION,
        "error": "X-PAYMENT header is required",
        "accepts": [{
            "scheme": SCHEME,
            "network": till.network,
            "maxAmountRequired": price.minor.to_string(),
            "resource": price.resource,
            "description": price.description,
            "mimeType": "application/json",
            "payTo": till.pay_to.to_string(),
            "maxTimeoutSeconds": till.max_timeout_seconds,
            "asset": till.asset.to_string(),
            "extra": { "name": till.asset_name, "version": till.asset_version },
        }],
    })
}

/// The transfer the payer authorized (EIP-3009).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// The payer.
    pub from: Address,
    /// The recipient.
    pub to: Address,
    /// Amount, minor units.
    pub value: u128,
    /// Not valid before this second (Unix time).
    pub valid_after: u64,
    /// Not valid from this second on.
    pub valid_before: u64,
    /// The payer's unique nonce.
    pub nonce: [u8; 32],
}

impl Authorization {
    /// The EIP-712 digest the payer signed, under the till's token domain.
    #[must_use]
    pub fn digest(&self, till: &Till) -> [u8; 32] {
        let s = keccak(&[
            &keccak(&[TWA_TYPE]),
            &word_addr(&self.from),
            &word_addr(&self.to),
            &word_u128(self.value),
            &word_u128(u128::from(self.valid_after)),
            &word_u128(u128::from(self.valid_before)),
            &self.nonce,
        ]);
        keccak(&[b"\x19\x01", &till.domain_separator(), &s])
    }
}

/// Authorizations already taken: one per payer and nonce, ever.
pub trait Nonces {
    /// Marks it taken; `false` if it already was.
    fn take(&mut self, from: &Address, nonce: &[u8; 32]) -> bool;
}

impl Nonces for BTreeSet<(Address, [u8; 32])> {
    fn take(&mut self, from: &Address, nonce: &[u8; 32]) -> bool {
        self.insert((*from, *nonce))
    }
}

/// A payment accepted — the `bare` may be handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paid {
    /// What was authorized; settlement submits exactly this.
    pub authorization: Authorization,
    /// The 65-byte signature, for settlement.
    pub signature: [u8; 65],
}

/// Why a payment is not accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Not an x402 payment we can read.
    Malformed(String),
    /// Another version, scheme, network, token or recipient.
    NotOurs(String),
    /// Less than the price.
    Underpaid {
        /// Asked.
        asked: u128,
        /// Authorized.
        offered: u128,
    },
    /// Before `validAfter`.
    NotYetValid,
    /// At or past `validBefore`.
    Expired,
    /// The signature is not the payer's over this authorization.
    BadSignature,
    /// This authorization was taken before.
    Replayed,
}

/// Checks the `X-PAYMENT` header against the till and the price at `now`
/// (Unix seconds) and takes the authorization, so it is never taken twice.
/// Nothing is taken unless every check passes.
///
/// # Errors
///
/// [`Refused`], naming what does not hold.
pub fn accept(
    till: &Till,
    price: &Price,
    header: &str,
    now: u64,
    taken: &mut impl Nonces,
) -> Result<Paid, Refused> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(header.trim())
        .map_err(|_| Refused::Malformed("X-PAYMENT is not base64".into()))?;
    let v: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|_| Refused::Malformed("X-PAYMENT is not JSON".into()))?;
    let field = |o: &serde_json::Value, k: &str| -> Result<serde_json::Value, Refused> {
        o.get(k)
            .cloned()
            .ok_or_else(|| Refused::Malformed(format!("no {k}")))
    };
    let text = |o: &serde_json::Value, k: &str| -> Result<String, Refused> {
        field(o, k)?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Refused::Malformed(format!("{k} is not text")))
    };
    if field(&v, "x402Version")?.as_u64() != Some(X402_VERSION) {
        return Err(Refused::NotOurs("x402Version".into()));
    }
    if text(&v, "scheme")? != SCHEME {
        return Err(Refused::NotOurs("scheme".into()));
    }
    if text(&v, "network")? != till.network {
        return Err(Refused::NotOurs("network".into()));
    }
    let payload = field(&v, "payload")?;
    let a = field(&payload, "authorization")?;
    let addr = |k: &str| text(&a, k).and_then(|s| Address::parse(&s).map_err(Refused::Malformed));
    let auth = Authorization {
        from: addr("from")?,
        to: addr("to")?,
        value: dec_u128(&text(&a, "value")?)?,
        valid_after: dec_u64(&text(&a, "validAfter")?)?,
        valid_before: dec_u64(&text(&a, "validBefore")?)?,
        nonce: hex_n::<32>(&text(&a, "nonce")?, "nonce")?,
    };
    let signature = hex_n::<65>(&text(&payload, "signature")?, "signature")?;

    if auth.to != till.pay_to {
        return Err(Refused::NotOurs(format!("recipient {}", auth.to)));
    }
    if auth.value < price.minor {
        return Err(Refused::Underpaid {
            asked: price.minor,
            offered: auth.value,
        });
    }
    if now < auth.valid_after {
        return Err(Refused::NotYetValid);
    }
    if now >= auth.valid_before {
        return Err(Refused::Expired);
    }
    if recover(&auth.digest(till), &signature)? != auth.from {
        return Err(Refused::BadSignature);
    }
    if !taken.take(&auth.from, &auth.nonce) {
        return Err(Refused::Replayed);
    }
    Ok(Paid {
        authorization: auth,
        signature,
    })
}

/// What the issuer may do with one person asking for a `bare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Handover {
    /// The first `bare` of this release and version for this person: free.
    Free,
    /// A repeat, and the payment was accepted.
    Paid(Box<Paid>),
}

/// The check **before** a `bare` is handed over (`[decision]` 06.10): free the
/// first time; a repeat — `already_issued`, an issuance anchor matched — only
/// against an accepted payment. Without one the answer is the 402 body.
///
/// # Errors
///
/// `Err(Ok(body))` — pay first, with the body of the 402 answer;
/// `Err(Err(refused))` — a payment came and was not accepted.
pub fn before_handover(
    till: &Till,
    price: &Price,
    already_issued: bool,
    x_payment: Option<&str>,
    now: u64,
    taken: &mut impl Nonces,
) -> Result<Handover, Result<serde_json::Value, Refused>> {
    if !already_issued {
        return Ok(Handover::Free);
    }
    let Some(h) = x_payment else {
        return Err(Ok(payment_required(till, price)));
    };
    accept(till, price, h, now, taken)
        .map(|p| Handover::Paid(Box::new(p)))
        .map_err(Err)
}

/// The address that signed `digest`. High-s signatures are refused: each
/// payment has one signature, not two (EIP-2).
///
/// # Errors
///
/// [`Refused::BadSignature`].
pub fn recover(digest: &[u8; 32], sig: &[u8; 65]) -> Result<Address, Refused> {
    let rec = match sig[64] {
        0 | 27 => 0,
        1 | 28 => 1,
        _ => return Err(Refused::BadSignature),
    };
    let s = Signature::from_slice(&sig[..64]).map_err(|_| Refused::BadSignature)?;
    if s.normalize_s().is_some() {
        return Err(Refused::BadSignature);
    }
    let id = RecoveryId::from_byte(rec).ok_or(Refused::BadSignature)?;
    let key =
        VerifyingKey::recover_from_prehash(digest, &s, id).map_err(|_| Refused::BadSignature)?;
    let point = key.to_encoded_point(false);
    let h = keccak(&[&point.as_bytes()[1..]]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    Ok(Address(a))
}

fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut k = Keccak256::new();
    for p in parts {
        k.update(p);
    }
    k.finalize().into()
}

fn word_addr(a: &Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a.0);
    w
}

fn word_u128(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

fn dec_u128(s: &str) -> Result<u128, Refused> {
    if s.is_empty() || s.len() > 39 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Refused::Malformed(format!("{s:?} is not a decimal amount")));
    }
    s.parse()
        .map_err(|_| Refused::Malformed(format!("{s:?} is out of range")))
}

fn dec_u64(s: &str) -> Result<u64, Refused> {
    u64::try_from(dec_u128(s)?).map_err(|_| Refused::Malformed(format!("{s:?} is out of range")))
}

fn hex_n<const N: usize>(s: &str, what: &str) -> Result<[u8; N], Refused> {
    let h = s
        .strip_prefix("0x")
        .ok_or_else(|| Refused::Malformed(format!("{what}: no 0x")))?;
    hex::decode(h)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| Refused::Malformed(format!("{what}: not {N} bytes of hex")))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent vector: eth-account 0.13.4 (Python), key 0x11…11,
    // `sign_typed_data` over the same domain and message.
    const PAYER: &str = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A";
    const ISSUER: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
    const DIGEST: &str = "e651273bbc3ba2b8cab7f0588dcb94aaf5fd04a1c7ac61512c0df2225dc52064";
    const SIG: &str = "2a895ae6947395e7203111cc46aae30fb17b34185d92e5dc3af39b1f0047a97a0c6e8b4874c9e32469ab305eae18a3e23895f84a878ed4d905652f33f43878421c";
    const AFTER: u64 = 1_760_000_000;
    const BEFORE: u64 = 1_760_000_600;

    fn till() -> Till {
        Till::base_sepolia(Address::parse(ISSUER).unwrap())
    }

    fn price(minor: u128) -> Price {
        Price {
            minor,
            resource: "https://issuer.example/bare/issue".into(),
            description: "a repeated bare of release 2026-10, software 2.0.0".into(),
        }
    }

    fn header_with(edit: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut v = serde_json::json!({
            "x402Version": 1,
            "scheme": "exact",
            "network": "base-sepolia",
            "payload": {
                "signature": format!("0x{SIG}"),
                "authorization": {
                    "from": PAYER,
                    "to": ISSUER,
                    "value": "100000",
                    "validAfter": AFTER.to_string(),
                    "validBefore": BEFORE.to_string(),
                    "nonce": format!("0x{}", "ab".repeat(32)),
                }
            }
        });
        edit(&mut v);
        base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(&v).unwrap())
    }

    fn header() -> String {
        header_with(|_| {})
    }

    #[test]
    fn eip712_domain_matches_the_specification_example() {
        // EIP-712's own example: "Ether Mail", version 1, chain 1.
        let t = Till {
            network: String::new(),
            chain_id: 1,
            asset: Address::parse("0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC").unwrap(),
            asset_name: "Ether Mail".into(),
            asset_version: "1".into(),
            pay_to: Address([0; 20]),
            max_timeout_seconds: 0,
        };
        assert_eq!(
            hex::encode(t.domain_separator()),
            "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f"
        );
    }

    #[test]
    fn digest_and_signer_agree_with_an_independent_implementation() {
        let mut taken = BTreeSet::new();
        let paid = accept(&till(), &price(100_000), &header(), AFTER + 10, &mut taken).unwrap();
        assert_eq!(hex::encode(paid.authorization.digest(&till())), DIGEST);
        assert_eq!(paid.authorization.from, Address::parse(PAYER).unwrap());
    }

    #[test]
    fn the_same_authorization_is_taken_once() {
        let mut taken = BTreeSet::new();
        accept(&till(), &price(100_000), &header(), AFTER, &mut taken).unwrap();
        assert_eq!(
            accept(&till(), &price(100_000), &header(), AFTER, &mut taken),
            Err(Refused::Replayed)
        );
    }

    #[test]
    fn a_refusal_takes_nothing() {
        let mut taken = BTreeSet::new();
        assert!(accept(&till(), &price(100_001), &header(), AFTER, &mut taken).is_err());
        assert!(taken.is_empty());
        accept(&till(), &price(100_000), &header(), AFTER, &mut taken).unwrap();
    }

    #[test]
    fn time_window_amount_and_recipient_are_enforced() {
        let mut t = BTreeSet::new();
        let h = header();
        assert_eq!(
            accept(&till(), &price(100_000), &h, AFTER - 1, &mut t),
            Err(Refused::NotYetValid)
        );
        assert_eq!(
            accept(&till(), &price(100_000), &h, BEFORE, &mut t),
            Err(Refused::Expired)
        );
        assert_eq!(
            accept(&till(), &price(200_000), &h, AFTER, &mut t),
            Err(Refused::Underpaid {
                asked: 200_000,
                offered: 100_000
            })
        );
        let other = Till::base_sepolia(Address([9; 20]));
        assert!(matches!(
            accept(&other, &price(100_000), &h, AFTER, &mut t),
            Err(Refused::NotOurs(_))
        ));
        // the same token on another chain is another domain
        let mut mainnet = till();
        mainnet.chain_id = 8453;
        assert_eq!(
            accept(&mainnet, &price(100_000), &h, AFTER, &mut t),
            Err(Refused::BadSignature)
        );
    }

    #[test]
    fn any_changed_field_breaks_the_signature() {
        let edits: Vec<(&str, serde_json::Value)> = vec![
            ("value", "100001".into()),
            ("validBefore", (BEFORE + 1).to_string().into()),
            ("validAfter", (AFTER - 1).to_string().into()),
            ("nonce", format!("0x{}", "ac".repeat(32)).into()),
            ("from", ISSUER.into()),
        ];
        for (k, val) in edits {
            let h = header_with(|v| v["payload"]["authorization"][k] = val.clone());
            let r = accept(&till(), &price(100_000), &h, AFTER, &mut BTreeSet::new());
            assert_eq!(r, Err(Refused::BadSignature), "changed {k}");
        }
    }

    #[test]
    fn a_high_s_twin_of_a_good_signature_is_refused() {
        // n - s with the parity flipped is the same point: the malleable twin.
        let sig = hex::decode(SIG).unwrap();
        let s = Signature::from_slice(&sig[..64]).unwrap();
        let (r, s_lo) = s.split_bytes();
        let twin_s = -*Signature::from_slice(&sig[..64]).unwrap().s();
        let mut twin = r.to_vec();
        twin.extend_from_slice(&twin_s.to_bytes());
        twin.push(if sig[64] == 27 { 28 } else { 27 });
        assert_ne!(twin[32..64], s_lo[..]);
        let h =
            header_with(|v| v["payload"]["signature"] = format!("0x{}", hex::encode(&twin)).into());
        assert_eq!(
            accept(&till(), &price(100_000), &h, AFTER, &mut BTreeSet::new()),
            Err(Refused::BadSignature)
        );
    }

    #[test]
    fn garbage_is_malformed_not_a_panic() {
        let mut t = BTreeSet::new();
        for h in ["", "!!!", "e30=", "bnVsbA=="] {
            assert!(matches!(
                accept(&till(), &price(1), h, AFTER, &mut t),
                Err(Refused::Malformed(_) | Refused::NotOurs(_))
            ));
        }
        for (k, val) in [
            ("value", "-1"),
            ("value", "1e6"),
            ("value", "9".repeat(40).as_str()),
            ("nonce", "0xab"),
        ] {
            let h = header_with(|v| v["payload"]["authorization"][k] = val.into());
            assert!(
                matches!(
                    accept(&till(), &price(1), &h, AFTER, &mut t),
                    Err(Refused::Malformed(_))
                ),
                "{k}={val}"
            );
        }
        let h = header_with(|v| v["scheme"] = "upto".into());
        assert_eq!(
            accept(&till(), &price(1), &h, AFTER, &mut t),
            Err(Refused::NotOurs("scheme".into()))
        );
    }

    #[test]
    fn the_402_answer_names_the_till_and_the_price() {
        let v = payment_required(&till(), &price(100_000));
        let a = &v["accepts"][0];
        assert_eq!(v["x402Version"], 1);
        assert_eq!(a["scheme"], "exact");
        assert_eq!(a["network"], "base-sepolia");
        assert_eq!(a["maxAmountRequired"], "100000");
        assert_eq!(a["payTo"], ISSUER.to_lowercase());
        assert_eq!(a["asset"], "0x036cbd53842c5426634e7929541ec2318f3dcf7e");
        assert_eq!(a["extra"]["name"], "USDC");
        assert_eq!(a["extra"]["version"], "2");
    }
}
