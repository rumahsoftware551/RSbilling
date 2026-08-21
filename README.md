# RS Billing

Fondasi aman untuk aplikasi billing ISP multi-tenant. Versi ini menjalankan aplikasi baru berbasis PHP 8.3 dan PDO tanpa mengekspos source Netbill 2015 ke web server.

## Status fase ini

Sudah tersedia:

- login aman dengan `password_hash` / `password_verify`;
- pembatasan lima percobaan login per 15 menit;
- proteksi CSRF, regenerasi session ID, idle timeout, dan secure headers;
- query PDO prepared statements;
- isolasi data menggunakan `tenant_id` untuk setiap ISP;
- role awal: owner, admin, billing, support, dan viewer;
- menu pengelolaan pengguna tenant untuk owner/admin dengan pencegahan eskalasi role;
- penggantian password mandiri dan kewajiban mengganti password sementara pada login pertama;
- penonaktifan akses staf per ISP tanpa memengaruhi tenant lain;
- master paket dan pelanggan dengan edit status, pencarian, filter, serta pagination;
- detail pelanggan, histori invoice/pembayaran, dan audit aktivitas;
- arsip aman pelanggan/paket tanpa menghapus histori transaksi;
- kalkulasi pajak, diskon, prorata, serta denda keterlambatan;
- tampilan invoice siap cetak atau disimpan sebagai PDF dari browser;
- laporan pendapatan tagihan, kas masuk, aging piutang, dan prioritas penagihan;
- import pelanggan CSV atomik serta export tagihan dan kas CSV yang aman untuk Excel;
- notification outbox WhatsApp/email per tenant dengan template invoice, idempotensi, retry, auto-cancel saat invoice selesai, dan audit;
- rekonsiliasi pembayaran CSV dengan staging, exact-match invoice/nominal, posting atomik, serta pencegahan referensi duplikat;
- credential vault perangkat jaringan terenkripsi per tenant dan simulator aman tanpa koneksi eksternal;
- penerbitan tagihan manual dan generator tagihan bulanan idempotent;
- filter periode/status tagihan, pembatalan tagihan belum dibayar, dan pencatatan pembayaran manual;
- audit log untuk perubahan data penting;
- runtime Docker dengan Nginx, PHP-FPM 8.3, dan MariaDB 11.4;
- pemeriksaan keamanan otomatis di GitHub Actions.

Source lama tetap berada di `netbill-master/` sebagai referensi migrasi. Konfigurasi Nginx hanya melayani folder `public/`, sehingga source lama dan file konfigurasi tidak dapat diakses dari browser.

Antrean notifikasi pada fase ini belum mengirim pesan ke provider eksternal. Pesan disimpan sebagai outbox internal sampai adapter WhatsApp/email, worker, dan kredensial tenant dikonfigurasi serta diuji.

## Menjalankan secara lokal

Persyaratan: Docker Engine dan Docker Compose v2.

```bash
cp .env.example .env
```

Edit `.env`, lalu ganti minimal nilai berikut dengan nilai unik:

- `DB_PASSWORD`
- `APP_KEY` (hasil `openssl rand -base64 32`, diawali `base64:`)
- `ADMIN_EMAIL`
- `ADMIN_PASSWORD` (minimal 12 karakter)
- `ADMIN_TENANT_NAME`
- `ADMIN_TENANT_SLUG`

`APP_TIMEZONE` default-nya `Asia/Jakarta`. Ganti dengan zona waktu IANA ISP apabila operasional berada di wilayah lain agar tanggal jatuh tempo, denda, dan waktu cetak konsisten.

Password acak dapat dibuat dengan:

```bash
openssl rand -base64 32
```

Gunakan hasil berbeda untuk `DB_PASSWORD` dan `APP_KEY`. Jangan mengganti `APP_KEY` setelah perangkat
disimpan sebelum tersedia prosedur rotasi kunci, karena kredensial lama tidak akan dapat dibuka.

Jalankan aplikasi:

```bash
docker compose up -d --build
docker compose ps
```

Saat versi aplikasi diperbarui, jalankan kembali `docker compose up -d --build`. Installer akan menambahkan kolom skema baru secara idempotent tanpa menghapus data yang sudah ada.

Buka `http://localhost:8080`. Endpoint pemeriksaan layanan tersedia di `http://localhost:8080/health`. Tidak ada username atau password demo yang ditanam di source code.

## Pengaturan produksi wajib

- gunakan HTTPS dan set `SESSION_SECURE_COOKIE=true`;
- jangan membuka port database ke internet;
- simpan `.env` hanya di server dan jangan commit ke Git;
- buat backup database terenkripsi dan uji restore secara berkala;
- jalankan di balik reverse proxy dengan sertifikat TLS yang aktif;
- lakukan penetration test dan uji isolasi tenant sebelum menerima pembayaran nyata.

## Verifikasi

```bash
sh scripts/verify.sh
docker compose config
```

Baca [rencana pengembangan](docs/ROADMAP.md) dan [checklist perkembangan](docs/DEVELOPMENT_CHECKLIST.md) sebelum melanjutkan ke integrasi jaringan dan fitur SaaS komersial.
