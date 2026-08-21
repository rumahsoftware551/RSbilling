<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/helpers.php';
require_once dirname(__DIR__) . '/app/PasswordPolicy.php';

function expect(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, "GAGAL: {$message}\n");
        exit(1);
    }
}

expect(e('<script>') === '&lt;script&gt;', 'HTML escaping wajib aktif.');

$auth = file_get_contents(dirname(__DIR__) . '/app/Auth.php') ?: '';
$database = file_get_contents(dirname(__DIR__) . '/app/Database.php') ?: '';
$schema = file_get_contents(dirname(__DIR__) . '/database/schema.sql') ?: '';
$nginx = file_get_contents(dirname(__DIR__) . '/docker/nginx/default.conf') ?: '';
$envExample = file_get_contents(dirname(__DIR__) . '/.env.example') ?: '';
$routes = file_get_contents(dirname(__DIR__) . '/public/index.php') ?: '';
$notificationService = file_get_contents(dirname(__DIR__) . '/app/NotificationService.php') ?: '';
$reconciliationService = file_get_contents(dirname(__DIR__) . '/app/PaymentReconciliationService.php') ?: '';

expect(str_contains($auth, 'password_verify'), 'Login wajib memakai password_verify.');
expect(str_contains($auth, 'session_regenerate_id(true)'), 'Login wajib meregenerasi session ID.');
expect(str_contains($auth, "tu.status = 'active'"), 'Login wajib memeriksa status membership tenant.');
expect(substr_count($auth, "tu.status = 'active'") >= 2, 'Sesi aktif wajib memeriksa ulang status membership tenant.');
expect(str_contains($database, 'PDO::ATTR_EMULATE_PREPARES => false'), 'PDO native prepared statement wajib digunakan.');
expect(substr_count($schema, 'tenant_id') >= 20, 'Skema bisnis wajib memiliki isolasi tenant.');
expect(str_contains($schema, 'must_change_password'), 'Akun staf wajib mendukung penggantian password pertama.');
expect(str_contains($schema, "status ENUM('active', 'disabled')"), 'Membership tenant wajib dapat dinonaktifkan.');
expect(str_contains($nginx, 'root /var/www/html/public;'), 'Nginx hanya boleh melayani public directory.');
expect(!str_contains($envExample, 'DB_USERNAME=root'), 'Aplikasi baru tidak boleh memakai akun root database.');
expect(str_contains($envExample, 'GANTI_DENGAN_PASSWORD_DATABASE_KUAT'), 'Contoh environment wajib meminta password unik.');
expect(PasswordPolicy::isAcceptable('Kunci-Aman-RSBilling-2026!'), 'Password kuat seharusnya diterima.');
expect(!PasswordPolicy::isAcceptable('Admin@12345'), 'Password contoh wajib ditolak.');
expect(!PasswordPolicy::isAcceptable('pendek123'), 'Password pendek wajib ditolak.');
expect(str_contains($routes, "WHERE tu.tenant_id = :tenant_id AND tu.user_id = :user_id"), 'Perubahan role wajib dibatasi tenant aktif.');
expect(str_contains($routes, "audit_event(\$db, 'account.password_changed'"), 'Perubahan password wajib diaudit.');
expect(
    str_contains($auth, "['owner', 'admin', 'billing', 'viewer']")
        && str_contains($auth, 'public static function requireReportAccess()'),
    'Laporan keuangan wajib memiliki kontrol akses role tersendiri.'
);
expect(
    str_contains($routes, "Auth::requireBillingAccess();\n    verify_csrf();\n    \$upload = \$_FILES['csv_file']")
        && str_contains($routes, "WHERE tenant_id = :tenant_id AND customer_code IN")
        && str_contains($routes, "WHERE p.tenant_id = :tenant_id AND p.paid_at >= :date_from"),
    'Import dan export CSV wajib terlindungi CSRF serta isolasi tenant.'
);
expect(
    str_contains($routes, "if (\$path === '/notifications' && \$method === 'POST') {\n    Auth::requireBillingAccess();\n    verify_csrf();")
        && str_contains($notificationService, "WHERE i.id = :invoice_id AND i.tenant_id = :tenant_id")
        && str_contains($notificationService, 'WHERE invoice_id = :invoice_id AND tenant_id = :tenant_id')
        && str_contains($notificationService, "AND n.status IN ('failed', 'cancelled') AND i.status = 'unpaid'")
        && str_contains($schema, 'notification_outbox_tenant_idempotency_unique (tenant_id, idempotency_key)'),
    'Outbox notifikasi wajib terlindungi role, CSRF, isolasi tenant, dan idempotensi.'
);
expect(
    str_contains($routes, "if (\$path === '/reconciliation/import' && \$method === 'POST') {\n    Auth::requireBillingAccess();\n    verify_csrf();")
        && str_contains($reconciliationService, 'WHERE tenant_id = :tenant_id AND invoice_number IN')
        && str_contains($reconciliationService, ")\n                 FOR UPDATE")
        && str_contains($reconciliationService, 'WHERE r.id = :id AND r.tenant_id = :tenant_id LIMIT 1 FOR UPDATE')
        && str_contains($reconciliationService, "if (\$invoiceUpdate->rowCount() !== 1)")
        && str_contains($reconciliationService, "AND match_status = 'matched'")
        && str_contains($reconciliationService, "WHERE invoice_id = :invoice_id AND tenant_id = :tenant_id AND match_status = 'matched'")
        && str_contains($schema, 'payment_reconciliations_tenant_method_reference_unique'),
    'Rekonsiliasi wajib terlindungi CSRF, tenant scope, lock, status, dan referensi unik.'
);

$paths = [dirname(__DIR__) . '/app', dirname(__DIR__) . '/public', dirname(__DIR__) . '/database'];
foreach ($paths as $path) {
    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));
    foreach ($iterator as $file) {
        if (!$file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }
        $source = file_get_contents($file->getPathname()) ?: '';
        expect(!preg_match('/\bmysql_(query|connect|select_db|fetch_array)\s*\(/', $source), 'API mysql_* ditemukan di ' . $file->getPathname());
        expect(!preg_match('/\bmd5\s*\(/', $source), 'MD5 password ditemukan di ' . $file->getPathname());
    }
}

fwrite(STDOUT, "Security smoke test lulus.\n");
