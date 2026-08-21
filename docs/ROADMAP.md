# Roadmap menuju produk multi-ISP

## Fase 1 — Security & runtime baseline

Status: dikerjakan pada branch `codex/security-runtime-hardening`.

- runtime PHP 8.3 + Nginx + MariaDB;
- autentikasi aman dan rate limiting;
- skema tenant/user/role;
- pelanggan, paket, tagihan, pembayaran manual;
- audit log dan CI security smoke test.

## Fase 2 — Operasional billing

- CRUD lengkap dan pencarian/pagination;
- generator tagihan bulanan idempotent;
- pajak, diskon, prorata, denda, dan invoice PDF;
- notifikasi WhatsApp/email dengan antrean;
- rekonsiliasi pembayaran dan laporan kas;
- import pelanggan dari CSV dengan validasi.

## Fase 3 — Network automation

- integrasi MikroTik API dengan secret terenkripsi;
- FreeRADIUS dan proyeksi `radcheck`/`radreply`;
- suspend, disconnect, pembayaran, dan reaktivasi idempotent;
- retry queue, dead-letter handling, serta audit perintah perangkat;
- simulasi perangkat untuk test tanpa menyentuh jaringan produksi.

## Fase 4 — SaaS komersial

- onboarding dan provisioning tenant;
- paket langganan ISP, batas pemakaian, dan metering;
- portal owner, finance, CS, NOC, teknisi, reseller, dan pelanggan;
- branding per tenant, domain khusus, serta object storage terisolasi;
- MFA, SSO opsional, backup/restore per tenant, dan disaster recovery;
- observability, SLA, support tooling, kebijakan privasi, dan perjanjian layanan.
