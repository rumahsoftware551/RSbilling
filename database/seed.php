<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

$tenantName = trim((string) env('ADMIN_TENANT_NAME', ''));
$tenantSlug = strtolower(trim((string) env('ADMIN_TENANT_SLUG', '')));
$adminName = trim((string) env('ADMIN_NAME', ''));
$adminEmail = strtolower(trim((string) env('ADMIN_EMAIL', '')));
$adminPassword = (string) env('ADMIN_PASSWORD', '');

$blockedPasswords = [
    'GANTI_DENGAN_PASSWORD_ADMIN_KUAT',
    'ChangeMe123!',
    'Admin@12345',
];

if ($tenantName === '' || !preg_match('/^[a-z0-9][a-z0-9-]{1,78}[a-z0-9]$/', $tenantSlug)) {
    throw new RuntimeException('ADMIN_TENANT_NAME atau ADMIN_TENANT_SLUG tidak valid.');
}
if ($adminName === '' || !filter_var($adminEmail, FILTER_VALIDATE_EMAIL)) {
    throw new RuntimeException('ADMIN_NAME atau ADMIN_EMAIL tidak valid.');
}
if (strlen($adminPassword) < 12 || in_array($adminPassword, $blockedPasswords, true)) {
    throw new RuntimeException('ADMIN_PASSWORD wajib unik dan minimal 12 karakter; jangan gunakan nilai contoh.');
}

$db = Database::connection();
$db->beginTransaction();
try {
    $tenantQuery = $db->prepare('SELECT id FROM tenants WHERE slug = :slug LIMIT 1');
    $tenantQuery->execute(['slug' => $tenantSlug]);
    $tenantId = $tenantQuery->fetchColumn();
    if (!$tenantId) {
        $insertTenant = $db->prepare('INSERT INTO tenants (name, slug) VALUES (:name, :slug)');
        $insertTenant->execute(['name' => $tenantName, 'slug' => $tenantSlug]);
        $tenantId = (int) $db->lastInsertId();
    }

    $userQuery = $db->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
    $userQuery->execute(['email' => $adminEmail]);
    $userId = $userQuery->fetchColumn();
    $created = false;
    if (!$userId) {
        $insertUser = $db->prepare(
            'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)'
        );
        $insertUser->execute([
            'name' => $adminName,
            'email' => $adminEmail,
            'password_hash' => password_hash($adminPassword, PASSWORD_DEFAULT),
        ]);
        $userId = (int) $db->lastInsertId();
        $created = true;
    }

    $membership = $db->prepare(
        "INSERT INTO tenant_users (tenant_id, user_id, role)
         VALUES (:tenant_id, :user_id, 'owner')
         ON DUPLICATE KEY UPDATE role = VALUES(role)"
    );
    $membership->execute(['tenant_id' => $tenantId, 'user_id' => $userId]);

    $plan = $db->prepare(
        "INSERT INTO plans (tenant_id, code, name, speed_label, price)
         VALUES (:tenant_id, 'HOME-10', 'Home 10 Mbps', '10 Mbps', 150000)
         ON DUPLICATE KEY UPDATE name = VALUES(name)"
    );
    $plan->execute(['tenant_id' => $tenantId]);

    $db->commit();
    fwrite(STDOUT, $created ? "Administrator awal berhasil dibuat.\n" : "Administrator sudah tersedia.\n");
} catch (Throwable $exception) {
    $db->rollBack();
    throw $exception;
}
