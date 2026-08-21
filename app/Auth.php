<?php

declare(strict_types=1);

final class Auth
{
    private const MAX_ATTEMPTS = 5;

    public static function attempt(string $email, string $password, string $ipAddress): bool
    {
        $db = Database::connection();
        $email = strtolower(trim($email));
        if (strlen($email) > 190 || strlen($password) > 128) {
            return false;
        }
        $attemptKey = hash('sha256', $email . '|' . $ipAddress);

        $db->prepare('DELETE FROM login_attempts WHERE attempted_at < (NOW() - INTERVAL 1 DAY)')->execute();
        $count = $db->prepare(
            'SELECT COUNT(*) FROM login_attempts WHERE attempt_key = :attempt_key AND attempted_at >= (NOW() - INTERVAL 15 MINUTE)'
        );
        $count->execute(['attempt_key' => $attemptKey]);
        if ((int) $count->fetchColumn() >= self::MAX_ATTEMPTS) {
            return false;
        }

        $query = $db->prepare(
            "SELECT u.id, u.name, u.email, u.password_hash, u.must_change_password,
                    tu.role, tu.status AS membership_status,
                    t.id AS tenant_id, t.name AS tenant_name, t.slug AS tenant_slug
             FROM users u
             INNER JOIN tenant_users tu ON tu.user_id = u.id
             INNER JOIN tenants t ON t.id = tu.tenant_id
             WHERE u.email = :email AND u.status = 'active'
               AND tu.status = 'active' AND t.status = 'active'
             ORDER BY tu.id ASC
             LIMIT 1"
        );
        $query->execute(['email' => $email]);
        $user = $query->fetch();

        if (!$user || !password_verify($password, (string) $user['password_hash'])) {
            $record = $db->prepare('INSERT INTO login_attempts (attempt_key) VALUES (:attempt_key)');
            $record->execute(['attempt_key' => $attemptKey]);
            return false;
        }

        if (password_needs_rehash((string) $user['password_hash'], PASSWORD_DEFAULT)) {
            $rehash = $db->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
            $rehash->execute([
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
                'id' => $user['id'],
            ]);
        }

        $db->prepare('DELETE FROM login_attempts WHERE attempt_key = :attempt_key')
            ->execute(['attempt_key' => $attemptKey]);
        $db->prepare('UPDATE users SET last_login_at = NOW() WHERE id = :id')
            ->execute(['id' => $user['id']]);

        session_regenerate_id(true);
        unset($user['password_hash']);
        $_SESSION['auth'] = $user;
        $_SESSION['last_activity'] = time();
        $_SESSION['_csrf'] = bin2hex(random_bytes(32));
        return true;
    }

    public static function check(): bool
    {
        return isset($_SESSION['auth']['id'], $_SESSION['auth']['tenant_id']);
    }

    public static function requireLogin(): void
    {
        if (!self::check()) {
            flash('error', 'Silakan masuk untuk melanjutkan.');
            redirect('/login');
        }

        $user = self::user();
        $authorization = Database::connection()->prepare(
            "SELECT u.name, u.email, u.must_change_password, tu.role,
                    t.name AS tenant_name, t.slug AS tenant_slug
             FROM users u
             INNER JOIN tenant_users tu ON tu.user_id = u.id
             INNER JOIN tenants t ON t.id = tu.tenant_id
             WHERE u.id = :user_id AND t.id = :tenant_id
               AND u.status = 'active' AND tu.status = 'active' AND t.status = 'active'
             LIMIT 1"
        );
        $authorization->execute([
            'user_id' => (int) $user['id'],
            'tenant_id' => (int) $user['tenant_id'],
        ]);
        $current = $authorization->fetch();

        if (!$current) {
            self::logout();
            session_start();
            flash('error', 'Akses akun telah dinonaktifkan. Hubungi administrator ISP.');
            redirect('/login');
        }

        $_SESSION['auth'] = array_merge($user, $current);
    }

    public static function user(): array
    {
        return is_array($_SESSION['auth'] ?? null) ? $_SESSION['auth'] : [];
    }

    public static function tenantId(): int
    {
        return (int) ($_SESSION['auth']['tenant_id'] ?? 0);
    }

    public static function canManageBilling(): bool
    {
        return in_array((string) ($_SESSION['auth']['role'] ?? ''), ['owner', 'admin', 'billing'], true);
    }

    public static function canManageUsers(): bool
    {
        return in_array((string) ($_SESSION['auth']['role'] ?? ''), ['owner', 'admin'], true);
    }

    public static function canViewReports(): bool
    {
        return in_array((string) ($_SESSION['auth']['role'] ?? ''), ['owner', 'admin', 'billing', 'viewer'], true);
    }

    public static function requireBillingAccess(): void
    {
        self::requireLogin();
        if (!self::canManageBilling()) {
            http_response_code(403);
            exit('Anda tidak memiliki izin untuk mengubah data billing.');
        }
    }

    public static function requireUserManagement(): void
    {
        self::requireLogin();
        if (!self::canManageUsers()) {
            http_response_code(403);
            exit('Anda tidak memiliki izin untuk mengelola pengguna.');
        }
    }

    public static function requireReportAccess(): void
    {
        self::requireLogin();
        if (!self::canViewReports()) {
            http_response_code(403);
            exit('Anda tidak memiliki izin untuk melihat laporan keuangan.');
        }
    }

    public static function logout(): void
    {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
    }
}
