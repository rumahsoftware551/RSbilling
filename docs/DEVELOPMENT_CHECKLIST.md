# Checklist pengembangan RS Billing

Pembaruan terakhir: 21 Agustus 2026

Checklist ini diperbarui setiap kali satu milestone selesai dan telah melewati pemeriksaan otomatis.

## Fase 1 — Security dan runtime

- [x] PHP 8.3 FPM, Nginx, MariaDB, dan Docker Compose
- [x] health endpoint dan installer database idempotent
- [x] password hashing, CSRF, session hardening, dan login throttling
- [x] PDO native prepared statements dan isolasi `tenant_id`
- [x] security headers, audit log, dan GitHub Actions

## Fase 1.1 — Identity dan access

- [x] role owner, admin, billing, support, dan viewer
- [x] penggantian password mandiri
- [x] password sementara dan kewajiban ganti password
- [x] pengelolaan pengguna serta role per tenant
- [x] penonaktifan membership dan validasi ulang sesi

## Fase 2 — Operasional billing

- [x] master paket dan pelanggan
- [x] edit status, pencarian, filter, dan pagination
- [x] generator tagihan bulanan idempotent
- [x] invoice manual dan pembayaran manual
- [x] filter invoice berdasarkan status, periode, dan pencarian
- [x] pembatalan invoice belum dibayar
- [x] detail pelanggan dan histori invoice
- [x] detail invoice dan histori pembayaran
- [x] arsip pelanggan/paket tanpa menghapus histori
- [x] pajak dan diskon
- [x] prorata dan denda keterlambatan idempotent
- [x] invoice siap cetak dan disimpan sebagai PDF melalui browser
- [ ] laporan piutang, pendapatan, dan kas
- [ ] import pelanggan CSV dan export laporan
- [ ] notifikasi WhatsApp/email dengan antrean
- [ ] rekonsiliasi pembayaran

## Fase 3 — Network automation

- [ ] penyimpanan credential MikroTik terenkripsi
- [ ] integrasi MikroTik API
- [ ] FreeRADIUS dan proyeksi `radcheck`/`radreply`
- [ ] suspend, disconnect, dan reaktivasi idempotent
- [ ] retry queue, dead-letter handling, dan simulator perangkat

## Fase 4 — SaaS komersial

- [ ] onboarding dan provisioning tenant
- [ ] paket langganan, batas pemakaian, dan metering
- [ ] portal owner, finance, CS, NOC, teknisi, reseller, dan pelanggan
- [ ] branding serta domain per tenant
- [ ] MFA, backup/restore, monitoring, dan disaster recovery
- [ ] dokumentasi operasional, SLA, privasi, dan perjanjian layanan

## Gerbang rilis

- [ ] seluruh test otomatis lulus
- [ ] uji isolasi tenant lulus
- [ ] uji backup dan restore lulus
- [ ] uji satu siklus billing penuh lulus
- [ ] uji suspend–bayar–reaktivasi lulus
- [ ] UAT pada ISP pilot lulus
- [ ] penetration test dan load test lulus
