<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/BillingService.php';
require_once dirname(__DIR__) . '/app/CsvService.php';
require_once dirname(__DIR__) . '/app/CustomerImportService.php';
require_once dirname(__DIR__) . '/app/NotificationService.php';
require_once dirname(__DIR__) . '/app/PaymentReconciliationService.php';
require_once dirname(__DIR__) . '/app/Pagination.php';
require_once dirname(__DIR__) . '/app/ReportService.php';

function assert_operational(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "GAGAL: {$message}\n");
        exit(1);
    }
}

assert_operational(BillingService::periodStart('2026-08') === '2026-08-01', 'Periode bulanan harus dinormalisasi.');
assert_operational(BillingService::periodStart('2026-13') === null, 'Bulan tidak valid wajib ditolak.');
assert_operational(BillingService::monthLabel('2026-08') === 'Agustus 2026', 'Label bulan Indonesia harus konsisten.');
assert_operational(
    BillingService::invoiceNumber('2026-08', 42, 'CUST-001') === 'INV-202608-42-CUST-001',
    'Nomor invoice bulanan harus deterministik.'
);
assert_operational(BillingService::daysInMonth('2028-02') === 29, 'Jumlah hari periode harus mendukung tahun kabisat.');

$totals = BillingService::calculateTotals(100000, 11, 10000);
assert_operational($totals['subtotal'] === 100000.0, 'Subtotal penuh tidak sesuai.');
assert_operational($totals['tax_amount'] === 9900.0, 'Pajak setelah diskon tidak sesuai.');
assert_operational($totals['amount'] === 99900.0, 'Total setelah diskon dan pajak tidak sesuai.');

$prorated = BillingService::calculateTotals(100000, 0, 0, 15, 30);
assert_operational($prorated['subtotal'] === 50000.0, 'Perhitungan prorata tidak sesuai.');
assert_operational(
    BillingService::totalWithPenalty(50000, 0, 0, 5000) === 55000.0,
    'Penetapan denda absolut tidak sesuai.'
);

$invalidDiscountRejected = false;
try {
    BillingService::calculateTotals(50000, 0, 51000);
} catch (InvalidArgumentException) {
    $invalidDiscountRejected = true;
}
assert_operational($invalidDiscountRejected, 'Diskon di atas subtotal wajib ditolak.');

$invalidProrationRejected = false;
try {
    BillingService::calculateTotals(50000, 0, 0, 31, 30);
} catch (InvalidArgumentException) {
    $invalidProrationRejected = true;
}
assert_operational($invalidProrationRejected, 'Hari prorata di luar periode wajib ditolak.');

$range = ReportService::normalizeRange('2026-08-01', '2026-08-31');
assert_operational($range['inclusive_days'] === 31, 'Jumlah hari laporan tidak sesuai.');
assert_operational($range['end_before'] === '2026-09-01 00:00:00', 'Batas eksklusif laporan tidak sesuai.');
$agingBoundaries = ReportService::agingBoundaries('2026-08-21');
assert_operational($agingBoundaries['day_30'] === '2026-07-22', 'Batas aging 30 hari tidak sesuai.');

$invalidRangeRejected = false;
try {
    ReportService::normalizeRange('2026-08-31', '2026-08-01');
} catch (InvalidArgumentException) {
    $invalidRangeRejected = true;
}
assert_operational($invalidRangeRejected, 'Rentang laporan terbalik wajib ditolak.');

$csvPath = tempnam(sys_get_temp_dir(), 'rsbilling-csv-');
assert_operational(is_string($csvPath), 'File sementara CSV wajib dapat dibuat.');
file_put_contents(
    $csvPath,
    "\xEF\xBB\xBFcustomer_code;name;phone;email;address;plan_code;status\n"
    . "CUST-001;Pelanggan Satu;0812;pelanggan@example.com;Alamat;PAKET-10M;active\n"
);
try {
    $importRows = CustomerImportService::parse($csvPath);
} finally {
    unlink($csvPath);
}
assert_operational(count($importRows) === 1, 'Parser CSV harus membaca satu pelanggan.');
assert_operational($importRows[0]['customer_code'] === 'CUST-001', 'BOM dan delimiter CSV harus diproses.');
assert_operational(CsvService::safeCell('=2+2') === "'=2+2", 'Formula injection CSV wajib dinetralkan.');
assert_operational(CsvService::safeCell(" \t@SUM(A1:A2)") === "' \t@SUM(A1:A2)", 'Formula tersamar wajib dinetralkan.');
assert_operational(CsvService::safeCell('Pelanggan Aman') === 'Pelanggan Aman', 'Sel CSV normal tidak boleh berubah.');

assert_operational(
    NotificationService::normalizeRecipient('whatsapp', '0812-3456-7890') === '6281234567890',
    'Nomor WhatsApp lokal harus dinormalisasi ke format internasional.'
);
assert_operational(
    NotificationService::normalizeRecipient('email', ' Billing@Example.COM ') === 'billing@example.com',
    'Email tujuan harus divalidasi dan dinormalisasi.'
);
$notificationContent = NotificationService::composeInvoice([
    'tenant_name' => 'ISP Uji',
    'customer_name' => 'Pelanggan Uji',
    'invoice_number' => 'INV-TEST-001',
    'period_label' => 'Agustus 2099',
    'amount' => '150000.00',
    'due_date' => '2099-08-20',
], 'whatsapp');
assert_operational($notificationContent['template'] === 'invoice_reminder', 'Template pengingat invoice tidak sesuai.');
assert_operational(
    str_contains($notificationContent['message'], 'INV-TEST-001')
        && str_contains($notificationContent['message'], 'Rp150.000'),
    'Isi pesan invoice wajib memuat nomor dan total tagihan.'
);

$reconciliationPath = tempnam(sys_get_temp_dir(), 'rsbilling-reconciliation-');
assert_operational(is_string($reconciliationPath), 'File sementara rekonsiliasi wajib dapat dibuat.');
file_put_contents(
    $reconciliationPath,
    "\xEF\xBB\xBFexternal_reference;invoice_number;amount;paid_at;method;payer_name\n"
    . "TRX-001;INV-TEST-001;150000,00;2026-08-20;bank_transfer;Pelanggan Uji\n"
);
try {
    $reconciliationRows = PaymentReconciliationService::parseCsv($reconciliationPath);
} finally {
    unlink($reconciliationPath);
}
assert_operational(count($reconciliationRows) === 1, 'Parser rekonsiliasi harus membaca satu transaksi.');
assert_operational($reconciliationRows[0]['amount'] === '150000.00', 'Nominal rekonsiliasi harus dinormalisasi.');
assert_operational(
    $reconciliationRows[0]['paid_at'] === '2026-08-20 00:00:00',
    'Tanggal rekonsiliasi harus dinormalisasi.'
);
$exactMatch = PaymentReconciliationService::classifyInvoice([
    'id' => 7,
    'amount' => '150000.00',
    'status' => 'unpaid',
], '150000.00');
assert_operational(
    $exactMatch['match_status'] === 'matched' && $exactMatch['invoice_id'] === 7,
    'Invoice dan nominal yang sama wajib berstatus matched.'
);
$amountMismatch = PaymentReconciliationService::classifyInvoice([
    'id' => 7,
    'amount' => '160000.00',
    'status' => 'unpaid',
], '150000.00');
assert_operational($amountMismatch['match_reason'] === 'amount_mismatch', 'Nominal berbeda wajib ditolak exact-match.');

$pagination = new Pagination(45, 3, 20);
assert_operational($pagination->page === 3, 'Halaman aktif tidak sesuai.');
assert_operational($pagination->offset() === 40, 'Offset pagination tidak sesuai.');
assert_operational($pagination->from() === 41 && $pagination->to() === 45, 'Rentang pagination tidak sesuai.');

$schema = file_get_contents(dirname(__DIR__) . '/database/schema.sql') ?: '';
$installer = file_get_contents(dirname(__DIR__) . '/database/install.php') ?: '';
$routes = file_get_contents(dirname(__DIR__) . '/public/index.php') ?: '';
$envExample = file_get_contents(dirname(__DIR__) . '/.env.example') ?: '';
assert_operational(
    str_contains($envExample, 'APP_TIMEZONE=Asia/Jakarta'),
    'Zona waktu aplikasi harus memiliki default eksplisit.'
);
assert_operational(
    str_contains($schema, 'invoices_tenant_customer_period_unique'),
    'Unique key invoice per tenant, pelanggan, dan periode wajib tersedia.'
);
assert_operational(
    str_contains($schema, 'base_amount DECIMAL(15,2)')
        && str_contains($schema, 'discount_amount DECIMAL(15,2)')
        && str_contains($schema, 'penalty_amount DECIMAL(15,2)'),
    'Komponen perhitungan invoice wajib disimpan terpisah.'
);
assert_operational(
    str_contains($schema, 'invoices_tenant_created_idx (tenant_id, created_at)'),
    'Index periode laporan invoice wajib tersedia.'
);
assert_operational(
    str_contains($schema, 'CREATE TABLE IF NOT EXISTS notification_outbox')
        && str_contains($schema, 'notification_outbox_tenant_idempotency_unique (tenant_id, idempotency_key)')
        && str_contains($schema, 'notification_outbox_tenant_queue_idx (tenant_id, status, available_at)'),
    'Outbox notifikasi wajib memiliki isolasi tenant, idempotensi, dan index antrean.'
);
assert_operational(
    str_contains($schema, 'CREATE TABLE IF NOT EXISTS payment_reconciliations')
        && str_contains($schema, 'payment_reconciliations_tenant_method_reference_unique')
        && str_contains($schema, 'payment_reconciliations_tenant_status_idx (tenant_id, match_status, created_at)'),
    'Staging rekonsiliasi wajib memiliki isolasi tenant, referensi unik, dan index status.'
);
assert_operational(
    str_contains($installer, "if (!\$columnExists(\$db, 'invoices', 'base_amount'))")
        && str_contains($installer, 'UPDATE invoices SET base_amount = amount, subtotal = amount'),
    'Migrasi komponen invoice wajib idempotent dan mem-backfill invoice lama.'
);
assert_operational(
    str_contains($routes, "BillingService::generateMonthly(\$db, \$tenantId"),
    'Route generator bulanan wajib menggunakan BillingService.'
);
assert_operational(
    str_contains($routes, "WHERE id = :id AND tenant_id = :tenant_id"),
    'Update master data wajib dibatasi tenant aktif.'
);
assert_operational(
    str_contains($routes, "if (\$path === '/customers/view')")
        && str_contains($routes, "if (\$path === '/invoices/view')"),
    'Halaman detail pelanggan dan invoice wajib tersedia.'
);
assert_operational(
    str_contains($routes, "audit_event(\$db, 'customer.archived'")
        && str_contains($routes, "audit_event(\$db, 'plan.archived'"),
    'Arsip pelanggan dan paket wajib masuk audit log.'
);
assert_operational(
    !str_contains($routes, 'DELETE FROM customers') && !str_contains($routes, 'DELETE FROM plans'),
    'Master data tidak boleh dihapus permanen melalui route operasional.'
);
assert_operational(
    str_contains($routes, 'p.invoice_id = :invoice_id AND p.tenant_id = :tenant_id'),
    'Histori pembayaran wajib dibatasi invoice dan tenant aktif.'
);
assert_operational(
    str_contains($routes, "audit_event(\$db, 'invoice.penalty_updated'")
        && str_contains($routes, "if (\$path === '/invoices/print')"),
    'Denda dan tampilan cetak invoice wajib tersedia.'
);
assert_operational(
    str_contains($routes, "if (\$path === '/reports' && \$method === 'GET')")
        && str_contains($routes, 'Auth::requireReportAccess()')
        && str_contains($routes, "FROM invoices WHERE tenant_id = :tenant_id AND status = 'unpaid'")
        && str_contains($routes, 'FROM payments')
        && str_contains($routes, 'WHERE tenant_id = :tenant_id AND paid_at >= :date_from'),
    'Laporan keuangan wajib tersedia, terlindungi role, dan dibatasi tenant aktif.'
);
assert_operational(
    str_contains($routes, "if (\$path === '/customers/import' && \$method === 'POST')")
        && str_contains($routes, 'is_uploaded_file')
        && str_contains($routes, "audit_event(\$db, 'customer.csv_imported'")
        && str_contains($routes, "if (\$path === '/reports/export' && \$method === 'GET')")
        && str_contains($routes, 'CsvService::writeRow'),
    'Import pelanggan dan export laporan CSV wajib tersedia serta diaudit.'
);
assert_operational(
    str_contains($routes, "if (\$path === '/notifications' && \$method === 'POST')")
        && str_contains($routes, 'NotificationService::enqueueInvoice(')
        && str_contains($routes, 'NotificationService::cancelInvoiceNotifications(')
        && str_contains($routes, "audit_event(\$db, 'notification.queued'")
        && str_contains($routes, "if (\$path === '/notifications' && \$method === 'GET')"),
    'Antrean notifikasi wajib memiliki enqueue, audit, dan halaman operasional.'
);
assert_operational(
    str_contains($routes, "if (\$path === '/reconciliation/import' && \$method === 'POST')")
        && str_contains($routes, 'PaymentReconciliationService::prepareRows(')
        && str_contains($routes, 'PaymentReconciliationService::post(')
        && str_contains($routes, 'PaymentReconciliationService::invalidateInvoiceMatches(')
        && str_contains($routes, "audit_event(\$db, 'payment.reconciled'")
        && str_contains($routes, "if (\$path === '/reconciliation' && \$method === 'GET')"),
    'Rekonsiliasi wajib memiliki import, exact-match, posting, audit, dan UI.'
);

fwrite(STDOUT, "Operational smoke test lulus.\n");
