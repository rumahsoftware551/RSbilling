<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/BillingService.php';
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

fwrite(STDOUT, "Operational smoke test lulus.\n");
