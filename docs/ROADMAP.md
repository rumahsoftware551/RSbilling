# Roadmap menuju produk multi-ISP

## Fase 1 — Security & runtime baseline

Status: dikerjakan pada branch `codex/security-runtime-hardening`.

- runtime PHP 8.3 + Nginx + MariaDB;
- autentikasi aman dan rate limiting;
- skema tenant/user/role;
- pelanggan, paket, tagihan, pembayaran manual;
- audit log dan CI security smoke test.

## Fase 1.1 — Identity & access operasional

Status: dikerjakan pada branch `codex/security-runtime-hardening`.

- penggantian password mandiri dengan verifikasi password lama;
- password sementara dan kewajiban ganti password saat login pertama;
- pengelolaan pengguna serta role oleh owner/admin;
- pembatasan eskalasi hak akses dan perlindungan akun owner;
- penonaktifan membership secara terpisah untuk setiap tenant.

## Fase 2 — Operasional billing

Status: sedang dikerjakan pada branch `codex/security-runtime-hardening`.

- [x] edit/status paket dan pelanggan dengan pencarian, filter, serta pagination;
- [x] generator tagihan bulanan idempotent;
- [x] filter periode/status dan pembatalan tagihan belum dibayar;
- [x] detail pelanggan/invoice, histori pembayaran, dan arsip data yang aman;
- [x] pajak, diskon, prorata, denda idempotent, dan invoice siap cetak/PDF;
- [x] laporan pendapatan tagihan, kas masuk, aging piutang, dan prioritas penagihan;
- [x] import pelanggan CSV tervalidasi serta export tagihan dan kas CSV;
- [x] notification outbox per tenant dengan template invoice, idempotensi, retry, auto-cancel invoice selesai, dan audit;
- adapter provider WhatsApp/email serta background worker;
- [x] rekonsiliasi pembayaran CSV dengan staging, exact-match, posting atomik, dan audit;
- adapter mutasi bank/payment gateway otomatis;

## Fase 3 — Network automation

- [x] credential vault terenkripsi per tenant dengan AES-256-GCM;
- [x] simulator perangkat tanpa socket atau koneksi jaringan eksternal;
- [x] command queue simulator dengan idempotensi, row lock, retry eksponensial, stale recovery, dead-letter, dan audit;
- integrasi MikroTik API nyata;
- FreeRADIUS dan proyeksi `radcheck`/`radreply`;
- suspend, disconnect, pembayaran, dan reaktivasi idempotent;
- [x] background worker permanen dengan heartbeat, healthcheck, restart policy, dan graceful shutdown;
- simulasi perangkat untuk test tanpa menyentuh jaringan produksi.

## Fase 4 — SaaS komersial

- onboarding dan provisioning tenant;
- paket langganan ISP, batas pemakaian, dan metering;
- portal owner, finance, CS, NOC, teknisi, reseller, dan pelanggan;
- branding per tenant, domain khusus, serta object storage terisolasi;
- MFA, SSO opsional, backup/restore per tenant, dan disaster recovery;
- observability, SLA, support tooling, kebijakan privasi, dan perjanjian layanan.
