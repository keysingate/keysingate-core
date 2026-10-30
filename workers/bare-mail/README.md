# ksg-bare-mail: verify@keysingate.com -> POST /v1/bare/mail

1. `cd workers/bare-mail && wrangler secret put KSG_WORKER_SECRET`
2. Edit `KSG_SERVICE_MAIL_URL` in `wrangler.toml` for your service.
3. `wrangler deploy` — deploys the Email Worker `ksg-bare-mail`.
4. Cloudflare Dashboard -> Email Routing -> Routing Rules: `verify@keysingate.com` -> Send to Worker -> `ksg-bare-mail`.
5. Turn off Catch-all so other people's mail does not reach the worker.
6. Mail to `verify+<id>@keysingate.com` is forwarded as `{"id","raw"}` to the service.
7. If the address has no id — `[<id>]` is looked up in the mail subject.
8. The secret travels in the `Authorization: Bearer ...` header, it is not in the code.
9. A service error (non-2xx) is written to Worker logs (`wrangler tail`).
10. No local emulation: Email Workers only via deploy + a live email.
