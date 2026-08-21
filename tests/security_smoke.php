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
$credentialVault = file_get_contents(dirname(__DIR__) . '/app/CredentialVault.php') ?: '';
$networkDeviceService = file_get_contents(dirname(__DIR__) . '/app/NetworkDeviceService.php') ?: '';
$networkCommandService = file_get_contents(dirname(__DIR__) . '/app/NetworkCommandService.php') ?: '';
$networkSimulator = file_get_contents(dirname(__DIR__) . '/app/NetworkDeviceSimulator.php') ?: '';
$networkWorker = file_get_contents(dirname(__DIR__) . '/scripts/network_worker.php') ?: '';
$networkWorkerDaemon = file_get_contents(dirname(__DIR__) . '/scripts/network_worker_daemon.php') ?: '';
$networkWorkerHealth = file_get_contents(dirname(__DIR__) . '/scripts/network_worker_health.php') ?: '';
$networkWorkerMonitor = file_get_contents(dirname(__DIR__) . '/app/NetworkWorkerMonitor.php') ?: '';
$compose = file_get_contents(dirname(__DIR__) . '/compose.yaml') ?: '';
$entrypoint = file_get_contents(dirname(__DIR__) . '/docker/php/entrypoint.sh') ?: '';
$workerComposeMatched = preg_match('/  network-worker:\n(?<block>.*?)(?=\nvolumes:)/s', $compose, $workerComposeMatch) === 1;
$workerCompose = $workerComposeMatched ? $workerComposeMatch['block'] : '';

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
expect(str_contains($envExample, 'APP_KEY=base64:'), 'Contoh environment wajib meminta key credential vault.');
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
expect(
    str_contains($auth, "['owner', 'admin']")
        && str_contains($auth, 'public static function requireNetworkAccess()')
        && str_contains($routes, "if (\$path === '/network-devices' && \$method === 'POST') {\n    Auth::requireNetworkAccess();\n    verify_csrf();")
        && str_contains($networkDeviceService, 'WHERE id = :id AND tenant_id = :tenant_id LIMIT 1 FOR UPDATE')
        && str_contains($schema, 'credential_ciphertext TEXT NOT NULL'),
    'Pengelolaan perangkat wajib dibatasi owner/admin, CSRF, tenant scope, dan ciphertext.'
);
expect(
    str_contains($credentialVault, "private const CIPHER = 'aes-256-gcm'")
        && str_contains($credentialVault, 'openssl_encrypt(')
        && str_contains($credentialVault, 'openssl_decrypt(')
        && str_contains($networkDeviceService, "'rsbilling|network-device|v1|'")
        && !preg_match('/\b(curl_|fsockopen|stream_socket_client|socket_create|gethostbyname)\s*\(/', $networkSimulator),
    'Vault wajib memakai authenticated encryption dan simulator tidak boleh membuka koneksi jaringan.'
);
expect(
    str_contains($routes, "if (\$path === '/network-commands' && \$method === 'POST') {\n    Auth::requireNetworkAccess();\n    verify_csrf();")
        && str_contains($networkCommandService, 'WHERE id = :id AND tenant_id = :tenant_id LIMIT 1')
        && str_contains($networkCommandService, 'WHERE tenant_id = :tenant_id AND customer_code = :customer_code LIMIT 1')
        && str_contains($networkCommandService, 'LIMIT 1 FOR UPDATE')
        && str_contains($networkCommandService, "status IN ('pending', 'retry_scheduled')")
        && str_contains($schema, 'network_commands_tenant_idempotency_unique (tenant_id, idempotency_key)')
        && str_contains($schema, 'network_commands_tenant_queue_idx (tenant_id, status, available_at)'),
    'Command queue wajib dibatasi role/CSRF, tenant scope, row lock, status, dan idempotensi.'
);
expect(
    str_contains($networkCommandService, "'dead_letter'")
        && str_contains($networkCommandService, 'recoverStale(')
        && str_contains($networkCommandService, 'retryDelaySeconds(')
        && str_contains($networkWorker, 'CredentialVault::fromEnvironment()')
        && !preg_match('/\b(curl_|fsockopen|stream_socket_client|socket_create|gethostbyname)\s*\(/', $networkCommandService . $networkWorker),
    'Worker simulator wajib memiliki retry/dead-letter tanpa primitive koneksi jaringan.'
);
expect(
    $workerComposeMatched
        && !str_contains($workerCompose, "\n    ports:")
        && str_contains($workerCompose, 'read_only: true')
        && str_contains($workerCompose, 'RSBILLING_SKIP_INSTALL: "1"')
        && str_contains($entrypoint, 'if [ "${RSBILLING_SKIP_INSTALL:-0}" != "1" ]')
        && str_contains($networkWorkerDaemon, 'NetworkCommandService::processDue($db, $vault, null')
        && str_contains($networkWorkerDaemon, 'pcntl_signal(SIGTERM')
        && str_contains($networkWorkerDaemon, 'pcntl_signal(SIGINT')
        && str_contains($networkWorkerDaemon, 'detail secret tidak disimpan')
        && str_contains($networkWorkerHealth, 'NetworkWorkerMonitor::isHealthy(')
        && !preg_match(
            '/\b(curl_|fsockopen|stream_socket_client|socket_create|gethostbyname)\s*\(/',
            $networkWorkerDaemon . $networkWorkerHealth . $networkWorkerMonitor
        ),
    'Daemon worker wajib simulator-only, tanpa port/koneksi jaringan, dan tidak menyimpan detail secret.'
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
