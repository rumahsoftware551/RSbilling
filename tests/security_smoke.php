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
