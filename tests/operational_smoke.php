<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/BillingService.php';
require_once dirname(__DIR__) . '/app/Pagination.php';

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

$pagination = new Pagination(45, 3, 20);
assert_operational($pagination->page === 3, 'Halaman aktif tidak sesuai.');
assert_operational($pagination->offset() === 40, 'Offset pagination tidak sesuai.');
assert_operational($pagination->from() === 41 && $pagination->to() === 45, 'Rentang pagination tidak sesuai.');

$schema = file_get_contents(dirname(__DIR__) . '/database/schema.sql') ?: '';
$routes = file_get_contents(dirname(__DIR__) . '/public/index.php') ?: '';
assert_operational(
    str_contains($schema, 'invoices_tenant_customer_period_unique'),
    'Unique key invoice per tenant, pelanggan, dan periode wajib tersedia.'
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

fwrite(STDOUT, "Operational smoke test lulus.\n");
