# ksg-bare-mail: verify@keysingate.com -> POST /v1/bare/mail

1. `cd workers/bare-mail && wrangler secret put KSG_WORKER_SECRET`
2. Отредактируй `KSG_SERVICE_MAIL_URL` в `wrangler.toml` под свой сервис.
3. `wrangler deploy` — деплоит Email Worker `ksg-bare-mail`.
4. Cloudflare Dashboard -> Email Routing -> Routing Rules: `verify@keysingate.com` -> Send to Worker -> `ksg-bare-mail`.
5. Catch-all выключи, чтобы чужая почта не шла в воркер.
6. Письмо на `verify+<id>@keysingate.com` форвардится как `{"id","raw"}` на сервис.
7. Если id нет в адресе — ищется `[<id>]` в теме письма.
8. Секрет едет заголовком `Authorization: Bearer ...`, в коде его нет.
9. Ошибка сервиса (не 2xx) пишется в Worker logs (`wrangler tail`).
10. Локально не эмулируется: Email Workers только через deploy + живое письмо.
