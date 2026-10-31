# What the demo claims — and where you can see it

Every claim below names the place where a judge can check it. **Stand** — shown in the hackathon
demo as it runs today (a test stand: one machine, test keys next to the container). **Product** —
true of the code and covered by its tests, but not shown on the judge page. What the demo does not
cover is listed at the end and in [`docs/after-the-demo.md`](../docs/after-the-demo.md).

## The insurance scene (`scripts/demo_orchestrator.sh`)

| # | Claim | Where you see it | Scope |
|---|---|---|---|
| 1 | An agent built on Muse Spark triages a synthetic insurance claim ([`case_4417.md`](case_4417.md)) and rejects it | the judge page: the decision page, REJECTED under clause 7.2 | stand |
| 2 | Every step lands as a signed page: the reading of the claim, the policy lookup, each model call, the damage mask | the judge page: pages in order, each with its tool call and hashes | stand |
| 3 | Every Muse Spark call becomes a page: model, request hash, answer hash (`ksg_model_call`) | the judge page: the model-call page | stand |
| 4 | The SAM 3.1 damage mask becomes a page: picture hash, box, mask hash (`ksg_mask_damage`) | the judge page: the mask page | stand |
| 5 | The expert re-asks SAM 3.1 with the same box; the mask hash matches byte for byte | the judge page, expert section ✓; [`scripts/expert_recheck_mask.py`](../scripts/expert_recheck_mask.py) | stand |
| 6 | The agent explains its decision for the judge; every sentence cites a page `[p:N]`, and a program — not a model — checks that each cited page exists and verifies offline | the judge page: "citations checked by program", clickable `[p:N]` | stand |
| 7 | An explanation that cites a missing or unverified page is refused | [`scripts/judge_explain.py`](../scripts/judge_explain.py) — such a citation lands in its refusals; on the judge page every citation is valid, so no refusal is shown | product |
| 8 | Each page verifies offline with the open-source checker, without our servers or the agent's platform | the judge page: the checker's verdict per page, `ACCEPTED (BoundPoint)` | stand |
| 9 | One changed word makes a page REJECTED | the judge page: "tampered copy: REJECTED" with the checker's reason | stand |
| 10 | The capsule is one 6 MiB file (6 291 456 bytes) and stays that size after writing | the judge page: capsule size before and after | stand |
| 11 | Only the named pages are disclosed; the rest stays sealed | the judge page renders the exported pages one by one | stand |
| 12 | The whole scene runs with one command | [`scripts/demo_orchestrator.sh`](../scripts/demo_orchestrator.sh); without a live run — the labelled sample [`demo/sample/judge_sample.html`](sample/judge_sample.html) | stand |
| 13 | The agent works through MCP tools (`ksg_get_container`, `ksg_write_page`, `ksg_model_call`, `ksg_mask_damage`, `ksg_export_page`, `ksg_verify`) and receives the claim through an ACP-A2A gateway | the tool calls recorded on the pages; [`scripts/ksg_mcp.py`](../scripts/ksg_mcp.py) | stand |

## The capsule and the anchored run

| # | Claim | Where you see it | Scope |
|---|---|---|---|
| 14 | The capsule file is indistinguishable from noise; each party holds one secret file; the parts are sealed to the parties' maps with X25519 + ML-KEM-768 | `crates/ksg-capsule-module`, `crates/ksg-container-v2` (capsule tests). On the stand both party files live on the same machine | product |
| 15 | The container's code runs inside the capsule: a WASM module in wasmtime behind two imports, a session open → call ×N → close | `crates/ksg-capsule-reader`, the `ksg-capsule` command line | product |
| 16 | Through the capsule, offline: print → initiation → three pages → export → each page ACCEPTED; a tampered page REJECTED; the capsule is 6 MiB after every step | [`scripts/demo_pro_capsule.sh`](../scripts/demo_pro_capsule.sh) — a separate run, not the judge page | stand |
| 17 | Pro with anchors on a local Solana node: through the capsule — initiation, journal opening with the owner's co-seal, three anchored pages exported and ACCEPTED, tampered pages REJECTED | one run: [`scripts/demo_pro_capsule_localnet.sh`](../scripts/demo_pro_capsule_localnet.sh) — brings up the node, prints the capsule with anchors, initiates and exports a page, then its verify half runs the test `k5_network_pro_through_the_capsule` (`crates/ksg-capsule-reader/tests/k5_offline.rs`): three pages ACCEPTED against the node, a flipped seal byte REJECTED; without the capsule — [`scripts/demo_pro_localnet.sh`](../scripts/demo_pro_localnet.sh) | stand (local node) |
| 18 | The container number is paid with x402 through μ Gate; the agent never holds a wallet key | [`scripts/e2e_ksg_x402.sh`](../scripts/e2e_ksg_x402.sh) — on the stand μ Gate pays from its test wallet and nothing is sent to a chain | stand (test wallet) |
| 19 | The client agent is named by the `did:key` of its own group key; two receivers never share an identifier | `crates/ksg-capsule-module` (session tests) | product |

## Precise wording

| Word | What exactly is meant |
|---|---|
| **post-quantum** | The container file is signed with ML-DSA-65 (FIPS 204). Pages and their seals are signed with Ed25519 |
| **verifies offline** | Signatures and the seal verify offline. The time of a page comes from its anchor on a public chain; checking that time needs the anchor |
| **a copy is seen** | At the next anchor, not instantly. Base (`light`): the second copy learns it is a copy when its next anchor is refused — before any export or transfer of rights. Solana (Pro): a rolled-back file is caught when a later copy anchored through the same payer ([`after-the-demo.md`](../docs/after-the-demo.md), Known limits) |
| **anchored** | The judge-page run does not anchor to a public chain. Anchored runs are on a local Solana node (claim 17) |

## Not in this demo

- **The agent never holds the wallet** — next step: gas for the anchors is paid through μ Gate under the owner's rules, the key out of the agent's reach. On the stand the anchors on the local Solana node are paid by a throw-away payer funded from the node's own faucet.
- Keys that the product keeps away from the issuer are, on the stand, generated and stored next to the container — the full list and what comes next: [`docs/after-the-demo.md`](../docs/after-the-demo.md).
