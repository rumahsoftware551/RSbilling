<?php

declare(strict_types=1);

require_once __DIR__ . '/helpers.php';
load_env_file(base_path('.env'));

$timezone = (string) env('APP_TIMEZONE', 'Asia/Jakarta');
if (!in_array($timezone, timezone_identifiers_list(), true)) {
    $timezone = 'UTC';
}
date_default_timezone_set($timezone);

$debug = (bool) env('APP_DEBUG', false);
ini_set('display_errors', $debug ? '1' : '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

spl_autoload_register(static function (string $class): void {
    $path = __DIR__ . '/' . basename(str_replace('\\', '/', $class)) . '.php';
    if (is_file($path)) {
        require_once $path;
    }
});

set_exception_handler(static function (Throwable $exception) use ($debug): void {
    error_log((string) $exception);
    if (PHP_SAPI !== 'cli') {
        http_response_code(500);
        echo $debug ? '<pre>' . e((string) $exception) . '</pre>' : 'Terjadi kesalahan internal. Silakan coba kembali.';
        return;
    }
    fwrite(STDERR, ($debug ? (string) $exception : $exception->getMessage()) . PHP_EOL);
    exit(1);
});

if (PHP_SAPI !== 'cli') {
    header_remove('X-Powered-By');
    header("Content-Security-Policy: default-src 'self'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'self'");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

    session_name('rsbilling_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => (bool) env('SESSION_SECURE_COOKIE', true),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    session_start();

    $config = require base_path('config/app.php');
    $lastActivity = (int) ($_SESSION['last_activity'] ?? 0);
    if ($lastActivity > 0 && (time() - $lastActivity) > $config['idle_timeout']) {
        Auth::logout();
        session_start();
        flash('error', 'Sesi berakhir karena tidak ada aktivitas. Silakan masuk kembali.');
    }
    $_SESSION['last_activity'] = time();
}
