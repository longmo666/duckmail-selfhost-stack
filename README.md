
# DuckMail Selfhost Stack (MVP)

This stack gives you:

- A selfhosted **domain admin page** (`/admin.html`)
- A temporary mailbox API (`/domains`, `/accounts`, `/token`, `/messages`, `/codes/latest`)
- SMTP capture with MailHog (for verification emails)

## 1) Start services

```bash
cp .env.example .env
# edit .env and set strong ADMIN_KEY/JWT_SECRET
docker compose up -d --build
```

API will listen on `127.0.0.1:8787`.

## 2) Nginx reverse proxy example

```nginx
server {
  listen 80;
  server_name main.yale.edu.kg;

  location / {
    proxy_pass http://127.0.0.1:8787;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

Then reload nginx:

```bash
nginx -t && systemctl reload nginx
```

## 3) DNS setup for each managed domain

For domain `example.com`:

- Set `MX` record: `example.com -> main.yale.edu.kg (priority 10)`
- Add TXT challenge from admin page:
  - name: `_duckmail-challenge.example.com`
  - value: token shown in admin page

After DNS propagates, click `验证 DNS` in `/admin.html`.

## 4) API quick examples

Create account:

```bash
curl -X POST http://127.0.0.1:8787/accounts \
  -H 'Content-Type: application/json' \
  -d '{"address":"bot@example.com","password":"strongpass123"}'
```

Login and get token:

```bash
curl -X POST http://127.0.0.1:8787/token \
  -H 'Content-Type: application/json' \
  -d '{"address":"bot@example.com","password":"strongpass123"}'
```

Get latest verification code:

```bash
curl http://127.0.0.1:8787/codes/latest \
  -H "Authorization: Bearer <token>"
```

## Notes

- This is an MVP for fast selfhosting and automation.
- It is not a full mail system like mailcow/mailu (no full anti-spam/queue/relay stack).
- For production-grade high-deliverability inboxing, add Postfix/Rspamd and stricter SMTP policies.

--------------------------zlK4i9zXvXwdRMq0fJvsI3--
