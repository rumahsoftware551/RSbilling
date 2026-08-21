<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$path = $path !== '/' ? rtrim($path, '/') : '/';
$db = Database::connection();

function audit_event(PDO $db, string $action, string $entityType, ?int $entityId = null, array $metadata = []): void
{
    $user = Auth::user();
    $statement = $db->prepare(
        'INSERT INTO audit_logs (tenant_id, user_id, action, entity_type, entity_id, metadata_json)
         VALUES (:tenant_id, :user_id, :action, :entity_type, :entity_id, :metadata_json)'
    );
    $statement->execute([
        'tenant_id' => Auth::tenantId(),
        'user_id' => (int) ($user['id'] ?? 0),
        'action' => $action,
        'entity_type' => $entityType,
        'entity_id' => $entityId,
        'metadata_json' => $metadata === [] ? null : json_encode($metadata, JSON_THROW_ON_ERROR),
    ]);
}

if ($path === '/health' && $method === 'GET') {
    $db->query('SELECT 1')->fetchColumn();
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['status' => 'ok'], JSON_THROW_ON_ERROR);
    exit;
}

if ($path === '/login' && $method === 'GET') {
    if (Auth::check()) {
        redirect('/');
    }
    View::header('Masuk', false);
    ?>
    <section class="auth-card">
        <div class="auth-mark">RS</div>
        <p class="eyebrow">Portal ISP</p>
        <h1>Masuk ke RS Billing</h1>
        <p class="muted">Gunakan akun ISP Anda. Sistem tidak menyediakan kredensial demo bawaan.</p>
        <form method="post" action="/login" class="stack-form">
            <?= csrf_field() ?>
            <label>Email
                <input type="email" name="email" autocomplete="username" maxlength="190" required autofocus>
            </label>
            <label>Password
                <input type="password" name="password" autocomplete="current-password" maxlength="128" required>
            </label>
            <button class="button button-primary button-full" type="submit">Masuk aman</button>
        </form>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/login' && $method === 'POST') {
    verify_csrf();
    $email = input('email');
    $password = input('password');
    $ip = (string) ($_SERVER['REMOTE_ADDR'] ?? 'unknown');
    if (filter_var($email, FILTER_VALIDATE_EMAIL) && Auth::attempt($email, $password, $ip)) {
        flash('success', 'Selamat datang kembali.');
        redirect('/');
    }
    flash('error', 'Email atau password tidak benar, atau percobaan login dibatasi sementara.');
    redirect('/login');
}

if ($path === '/logout' && $method === 'POST') {
    Auth::requireLogin();
    verify_csrf();
    Auth::logout();
    redirect('/login');
}

Auth::requireLogin();
$tenantId = Auth::tenantId();

if ((int) (Auth::user()['must_change_password'] ?? 0) === 1
    && !in_array($path, ['/account', '/account/password'], true)) {
    flash('error', 'Ganti password sementara sebelum menggunakan aplikasi.');
    redirect('/account');
}

if ($path === '/account/password' && $method === 'POST') {
    verify_csrf();
    $currentPassword = input('current_password');
    $newPassword = input('new_password');
    $confirmation = input('new_password_confirmation');

    if (!hash_equals($newPassword, $confirmation)) {
        flash('error', 'Konfirmasi password baru tidak sama.');
        redirect('/account');
    }
    if (!PasswordPolicy::isAcceptable($newPassword)) {
        flash('error', PasswordPolicy::requirement());
        redirect('/account');
    }

    $user = Auth::user();
    $passwordQuery = $db->prepare(
        "SELECT u.password_hash
         FROM users u
         INNER JOIN tenant_users tu ON tu.user_id = u.id
         WHERE u.id = :user_id AND tu.tenant_id = :tenant_id AND tu.status = 'active'
         LIMIT 1"
    );
    $passwordQuery->execute([
        'user_id' => (int) $user['id'],
        'tenant_id' => $tenantId,
    ]);
    $passwordHash = $passwordQuery->fetchColumn();

    if (!$passwordHash || !password_verify($currentPassword, (string) $passwordHash)) {
        flash('error', 'Password saat ini tidak benar.');
        redirect('/account');
    }
    if (password_verify($newPassword, (string) $passwordHash)) {
        flash('error', 'Password baru harus berbeda dari password saat ini.');
        redirect('/account');
    }

    $db->beginTransaction();
    try {
        $updatePassword = $db->prepare(
            'UPDATE users SET password_hash = :password_hash, must_change_password = 0 WHERE id = :user_id'
        );
        $updatePassword->execute([
            'password_hash' => password_hash($newPassword, PASSWORD_DEFAULT),
            'user_id' => (int) $user['id'],
        ]);
        audit_event($db, 'account.password_changed', 'user', (int) $user['id']);
        $db->commit();
    } catch (Throwable $exception) {
        if ($db->inTransaction()) {
            $db->rollBack();
        }
        throw $exception;
    }
    $_SESSION['auth']['must_change_password'] = 0;
    flash('success', 'Password berhasil diperbarui.');
    redirect('/account');
}

if ($path === '/users' && $method === 'POST') {
    Auth::requireUserManagement();
    verify_csrf();
    $operator = Auth::user();
    $operatorRole = (string) ($operator['role'] ?? '');
    $assignableRoles = $operatorRole === 'owner'
        ? ['admin', 'billing', 'support', 'viewer']
        : ['billing', 'support', 'viewer'];
    $action = input('_action', 'create');

    if ($action === 'create') {
        $name = input('name');
        $email = strtolower(input('email'));
        $password = input('password');
        $role = input('role');

        if ($name === '' || strlen($name) > 120 || !filter_var($email, FILTER_VALIDATE_EMAIL)
            || strlen($email) > 190 || !in_array($role, $assignableRoles, true)) {
            flash('error', 'Nama, email, atau role pengguna tidak valid.');
            redirect('/users');
        }
        if (!PasswordPolicy::isAcceptable($password)) {
            flash('error', PasswordPolicy::requirement());
            redirect('/users');
        }

        $db->beginTransaction();
        try {
            $existing = $db->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
            $existing->execute(['email' => $email]);
            if ($existing->fetchColumn()) {
                throw new DomainException('Email sudah digunakan oleh akun lain.');
            }

            $insertUser = $db->prepare(
                "INSERT INTO users (name, email, password_hash, status, must_change_password)
                 VALUES (:name, :email, :password_hash, 'active', 1)"
            );
            $insertUser->execute([
                'name' => $name,
                'email' => $email,
                'password_hash' => password_hash($password, PASSWORD_DEFAULT),
            ]);
            $userId = (int) $db->lastInsertId();

            $membership = $db->prepare(
                "INSERT INTO tenant_users (tenant_id, user_id, role, status)
                 VALUES (:tenant_id, :user_id, :role, 'active')"
            );
            $membership->execute([
                'tenant_id' => $tenantId,
                'user_id' => $userId,
                'role' => $role,
            ]);
            audit_event($db, 'user.created', 'user', $userId, ['role' => $role]);
            $db->commit();
            flash('success', 'Pengguna berhasil dibuat. Pengguna wajib mengganti password saat login pertama.');
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            if ($exception instanceof DomainException || ($exception instanceof PDOException && $exception->getCode() === '23000')) {
                flash('error', $exception instanceof DomainException ? $exception->getMessage() : 'Email sudah digunakan oleh akun lain.');
            } else {
                throw $exception;
            }
        }
        redirect('/users');
    }

    if ($action === 'update') {
        $userId = filter_var(input('user_id'), FILTER_VALIDATE_INT);
        $role = input('role');
        $status = input('status');
        if (!$userId || !in_array($role, $assignableRoles, true) || !in_array($status, ['active', 'disabled'], true)) {
            flash('error', 'Perubahan pengguna tidak valid.');
            redirect('/users');
        }
        if ($userId === (int) ($operator['id'] ?? 0)) {
            flash('error', 'Role dan akses akun sendiri tidak dapat diubah dari halaman ini.');
            redirect('/users');
        }

        $db->beginTransaction();
        try {
            $targetQuery = $db->prepare(
                'SELECT tu.role, tu.status
                 FROM tenant_users tu
                 WHERE tu.tenant_id = :tenant_id AND tu.user_id = :user_id
                 FOR UPDATE'
            );
            $targetQuery->execute(['tenant_id' => $tenantId, 'user_id' => $userId]);
            $target = $targetQuery->fetch();
            if (!$target) {
                throw new DomainException('Pengguna tidak ditemukan pada ISP ini.');
            }
            if ($target['role'] === 'owner' || ($operatorRole === 'admin' && $target['role'] === 'admin')) {
                throw new DomainException('Anda tidak dapat mengubah pengguna dengan tingkat akses tersebut.');
            }

            $updateMembership = $db->prepare(
                'UPDATE tenant_users SET role = :role, status = :status
                 WHERE tenant_id = :tenant_id AND user_id = :user_id'
            );
            $updateMembership->execute([
                'role' => $role,
                'status' => $status,
                'tenant_id' => $tenantId,
                'user_id' => $userId,
            ]);
            audit_event($db, 'user.membership_updated', 'user', (int) $userId, [
                'role' => $role,
                'status' => $status,
            ]);
            $db->commit();
            flash('success', 'Role dan status pengguna berhasil diperbarui.');
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            if ($exception instanceof DomainException) {
                flash('error', $exception->getMessage());
            } else {
                throw $exception;
            }
        }
        redirect('/users');
    }

    flash('error', 'Aksi pengguna tidak dikenali.');
    redirect('/users');
}

if ($path === '/customers' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $code = strtoupper(input('customer_code'));
    $name = input('name');
    $phone = input('phone');
    $email = input('email');
    $address = input('address');
    $planId = filter_var(input('plan_id'), FILTER_VALIDATE_INT) ?: null;

    if (!preg_match('/^[A-Z0-9._-]{2,30}$/', $code) || $name === '' || strlen($name) > 120) {
        flash('error', 'Kode atau nama pelanggan tidak valid.');
        redirect('/customers');
    }
    if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        flash('error', 'Format email pelanggan tidak valid.');
        redirect('/customers');
    }
    if ($planId !== null) {
        $planCheck = $db->prepare('SELECT id FROM plans WHERE id = :id AND tenant_id = :tenant_id AND status = \'active\'');
        $planCheck->execute(['id' => $planId, 'tenant_id' => $tenantId]);
        if (!$planCheck->fetchColumn()) {
            flash('error', 'Paket tidak ditemukan pada ISP ini.');
            redirect('/customers');
        }
    }

    try {
        $insert = $db->prepare(
            'INSERT INTO customers (tenant_id, plan_id, customer_code, name, phone, email, address)
             VALUES (:tenant_id, :plan_id, :customer_code, :name, :phone, :email, :address)'
        );
        $insert->execute([
            'tenant_id' => $tenantId,
            'plan_id' => $planId,
            'customer_code' => $code,
            'name' => $name,
            'phone' => substr($phone, 0, 30),
            'email' => $email !== '' ? $email : null,
            'address' => $address !== '' ? $address : null,
        ]);
        audit_event($db, 'customer.created', 'customer', (int) $db->lastInsertId(), ['code' => $code]);
        flash('success', 'Pelanggan berhasil ditambahkan.');
    } catch (PDOException $exception) {
        if ($exception->getCode() === '23000') {
            flash('error', 'Kode pelanggan sudah digunakan pada ISP ini.');
        } else {
            throw $exception;
        }
    }
    redirect('/customers');
}

if ($path === '/plans' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $code = strtoupper(input('code'));
    $name = input('name');
    $speed = input('speed_label');
    $price = filter_var(input('price'), FILTER_VALIDATE_FLOAT);
    if (!preg_match('/^[A-Z0-9._-]{2,30}$/', $code) || $name === '' || $speed === '' || $price === false || $price < 0) {
        flash('error', 'Data paket belum valid.');
        redirect('/plans');
    }
    try {
        $insert = $db->prepare(
            'INSERT INTO plans (tenant_id, code, name, speed_label, price)
             VALUES (:tenant_id, :code, :name, :speed_label, :price)'
        );
        $insert->execute([
            'tenant_id' => $tenantId,
            'code' => $code,
            'name' => substr($name, 0, 120),
            'speed_label' => substr($speed, 0, 80),
            'price' => $price,
        ]);
        audit_event($db, 'plan.created', 'plan', (int) $db->lastInsertId(), ['code' => $code]);
        flash('success', 'Paket internet berhasil ditambahkan.');
    } catch (PDOException $exception) {
        if ($exception->getCode() === '23000') {
            flash('error', 'Kode paket sudah digunakan pada ISP ini.');
        } else {
            throw $exception;
        }
    }
    redirect('/plans');
}

if ($path === '/invoices' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $action = input('_action', 'create');

    if ($action === 'pay') {
        $invoiceId = filter_var(input('invoice_id'), FILTER_VALIDATE_INT);
        if (!$invoiceId) {
            flash('error', 'Tagihan tidak valid.');
            redirect('/invoices');
        }
        $db->beginTransaction();
        try {
            $invoiceQuery = $db->prepare(
                "SELECT id, amount, status FROM invoices
                 WHERE id = :id AND tenant_id = :tenant_id FOR UPDATE"
            );
            $invoiceQuery->execute(['id' => $invoiceId, 'tenant_id' => $tenantId]);
            $invoice = $invoiceQuery->fetch();
            if (!$invoice || $invoice['status'] !== 'unpaid') {
                throw new DomainException('Tagihan tidak ditemukan atau sudah dibayar.');
            }
            $user = Auth::user();
            $payment = $db->prepare(
                "INSERT INTO payments (tenant_id, invoice_id, amount, method, recorded_by)
                 VALUES (:tenant_id, :invoice_id, :amount, 'manual', :recorded_by)"
            );
            $payment->execute([
                'tenant_id' => $tenantId,
                'invoice_id' => $invoiceId,
                'amount' => $invoice['amount'],
                'recorded_by' => (int) $user['id'],
            ]);
            $db->prepare("UPDATE invoices SET status = 'paid', paid_at = NOW() WHERE id = :id AND tenant_id = :tenant_id")
                ->execute(['id' => $invoiceId, 'tenant_id' => $tenantId]);
            audit_event($db, 'invoice.paid', 'invoice', (int) $invoiceId);
            $db->commit();
            flash('success', 'Pembayaran berhasil dicatat.');
        } catch (Throwable $exception) {
            $db->rollBack();
            if ($exception instanceof DomainException) {
                flash('error', $exception->getMessage());
            } else {
                throw $exception;
            }
        }
        redirect('/invoices');
    }

    $customerId = filter_var(input('customer_id'), FILTER_VALIDATE_INT);
    $amount = filter_var(input('amount'), FILTER_VALIDATE_FLOAT);
    $period = input('period_label');
    $dueDate = input('due_date');
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $dueDate);
    if (!$customerId || $amount === false || $amount <= 0 || $period === '' || !$date || $date->format('Y-m-d') !== $dueDate) {
        flash('error', 'Data tagihan belum valid.');
        redirect('/invoices');
    }
    $customer = $db->prepare('SELECT id FROM customers WHERE id = :id AND tenant_id = :tenant_id AND status != \'terminated\'');
    $customer->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
    if (!$customer->fetchColumn()) {
        flash('error', 'Pelanggan tidak ditemukan pada ISP ini.');
        redirect('/invoices');
    }
    $number = 'INV-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(3)));
    $insert = $db->prepare(
        'INSERT INTO invoices (tenant_id, customer_id, invoice_number, period_label, amount, due_date)
         VALUES (:tenant_id, :customer_id, :invoice_number, :period_label, :amount, :due_date)'
    );
    $insert->execute([
        'tenant_id' => $tenantId,
        'customer_id' => $customerId,
        'invoice_number' => $number,
        'period_label' => substr($period, 0, 40),
        'amount' => $amount,
        'due_date' => $dueDate,
    ]);
    audit_event($db, 'invoice.created', 'invoice', (int) $db->lastInsertId(), ['number' => $number]);
    flash('success', 'Tagihan berhasil diterbitkan.');
    redirect('/invoices');
}

if ($path === '/account') {
    $user = Auth::user();
    View::header('Akun Saya');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Keamanan akun</p><h1>Akun saya</h1></div>
        <span class="secure-badge">Sesi terlindungi</span>
    </div>
    <?php if ((int) ($user['must_change_password'] ?? 0) === 1): ?>
        <div class="notice notice-warning">
            Anda masih memakai password sementara. Ganti password sebelum membuka fitur lain.
        </div>
    <?php endif; ?>
    <section class="account-grid">
        <article class="panel">
            <h2>Profil akses</h2>
            <dl class="detail-list">
                <div><dt>Nama</dt><dd><?= e($user['name'] ?? '') ?></dd></div>
                <div><dt>Email</dt><dd><?= e($user['email'] ?? '') ?></dd></div>
                <div><dt>ISP</dt><dd><?= e($user['tenant_name'] ?? '') ?></dd></div>
                <div><dt>Role</dt><dd><span class="role-badge"><?= e($user['role'] ?? '') ?></span></dd></div>
            </dl>
        </article>
        <article class="panel">
            <h2>Ganti password</h2>
            <p class="muted form-help"><?= e(PasswordPolicy::requirement()) ?></p>
            <form method="post" action="/account/password" class="stack-form">
                <?= csrf_field() ?>
                <label>Password saat ini
                    <input type="password" name="current_password" autocomplete="current-password" maxlength="128" required>
                </label>
                <label>Password baru
                    <input type="password" name="new_password" autocomplete="new-password" minlength="12" maxlength="128" required>
                </label>
                <label>Ulangi password baru
                    <input type="password" name="new_password_confirmation" autocomplete="new-password" minlength="12" maxlength="128" required>
                </label>
                <button class="button button-primary" type="submit">Perbarui password</button>
            </form>
        </article>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/users') {
    Auth::requireUserManagement();
    $operator = Auth::user();
    $operatorRole = (string) ($operator['role'] ?? '');
    $assignableRoles = $operatorRole === 'owner'
        ? ['admin', 'billing', 'support', 'viewer']
        : ['billing', 'support', 'viewer'];
    $roleLabels = [
        'owner' => 'Owner',
        'admin' => 'Administrator',
        'billing' => 'Finance / Billing',
        'support' => 'Customer Support',
        'viewer' => 'Read Only',
    ];
    $usersQuery = $db->prepare(
        'SELECT u.id, u.name, u.email, u.last_login_at, u.must_change_password,
                tu.role, tu.status AS membership_status
         FROM tenant_users tu
         INNER JOIN users u ON u.id = tu.user_id
         WHERE tu.tenant_id = :tenant_id
         ORDER BY FIELD(tu.role, \'owner\', \'admin\', \'billing\', \'support\', \'viewer\'), u.name'
    );
    $usersQuery->execute(['tenant_id' => $tenantId]);
    $users = $usersQuery->fetchAll();

    View::header('Pengguna');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Kontrol akses</p><h1>Pengguna dan role</h1></div>
        <span class="secure-badge"><?= e(count($users)) ?> akun ISP</span>
    </div>
    <section class="panel">
        <h2>Tambah pengguna</h2>
        <p class="muted form-help">Buat password sementara yang unik. Pengguna akan diminta menggantinya saat login pertama.</p>
        <form method="post" class="form-grid">
            <?= csrf_field() ?>
            <input type="hidden" name="_action" value="create">
            <label>Nama lengkap
                <input name="name" maxlength="120" autocomplete="name" required>
            </label>
            <label>Email
                <input type="email" name="email" maxlength="190" autocomplete="email" required>
            </label>
            <label>Password sementara
                <input type="password" name="password" minlength="12" maxlength="128" autocomplete="new-password" required>
            </label>
            <label>Role
                <select name="role" required>
                    <?php foreach ($assignableRoles as $role): ?>
                        <option value="<?= e($role) ?>"><?= e($roleLabels[$role]) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <div class="field-wide"><button class="button button-primary" type="submit">Buat pengguna</button></div>
        </form>
    </section>
    <section class="panel">
        <h2>Daftar pengguna</h2>
        <div class="table-wrap">
            <table>
                <thead><tr><th>Pengguna</th><th>Role</th><th>Status</th><th>Login terakhir</th><th>Aksi</th></tr></thead>
                <tbody>
                <?php foreach ($users as $listedUser):
                    $isSelf = (int) $listedUser['id'] === (int) ($operator['id'] ?? 0);
                    $protectedRole = $listedUser['role'] === 'owner'
                        || ($operatorRole === 'admin' && $listedUser['role'] === 'admin');
                    $editable = !$isSelf && !$protectedRole;
                    ?>
                    <tr>
                        <td><strong><?= e($listedUser['name']) ?></strong><small><?= e($listedUser['email']) ?></small></td>
                        <td><span class="role-badge"><?= e($roleLabels[$listedUser['role']] ?? $listedUser['role']) ?></span></td>
                        <td>
                            <span class="status status-<?= e($listedUser['membership_status']) ?>"><?= e($listedUser['membership_status']) ?></span>
                            <?php if ((int) $listedUser['must_change_password'] === 1): ?><small>Password sementara</small><?php endif; ?>
                        </td>
                        <td><?= e($listedUser['last_login_at'] ?: 'Belum pernah') ?></td>
                        <td>
                            <?php if ($editable): ?>
                                <form method="post" class="user-row-form">
                                    <?= csrf_field() ?>
                                    <input type="hidden" name="_action" value="update">
                                    <input type="hidden" name="user_id" value="<?= e($listedUser['id']) ?>">
                                    <select name="role" aria-label="Role <?= e($listedUser['name']) ?>">
                                        <?php foreach ($assignableRoles as $role): ?>
                                            <option value="<?= e($role) ?>"<?= $listedUser['role'] === $role ? ' selected' : '' ?>><?= e($roleLabels[$role]) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                    <select name="status" aria-label="Status <?= e($listedUser['name']) ?>">
                                        <option value="active"<?= $listedUser['membership_status'] === 'active' ? ' selected' : '' ?>>Aktif</option>
                                        <option value="disabled"<?= $listedUser['membership_status'] === 'disabled' ? ' selected' : '' ?>>Nonaktif</option>
                                    </select>
                                    <button class="button button-small" type="submit">Simpan</button>
                                </form>
                            <?php else: ?>
                                <span class="muted"><?= $isSelf ? 'Akun Anda' : 'Dilindungi' ?></span>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/') {
    $counts = $db->prepare(
        "SELECT
            (SELECT COUNT(*) FROM customers WHERE tenant_id = :tenant_customers AND status = 'active') AS active_customers,
            (SELECT COUNT(*) FROM invoices WHERE tenant_id = :tenant_unpaid AND status = 'unpaid') AS unpaid_invoices,
            (SELECT COALESCE(SUM(amount), 0) FROM invoices WHERE tenant_id = :tenant_due AND status = 'unpaid') AS outstanding,
            (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE tenant_id = :tenant_revenue AND paid_at >= DATE_FORMAT(CURDATE(), '%Y-%m-01')) AS monthly_revenue"
    );
    $counts->execute([
        'tenant_customers' => $tenantId,
        'tenant_unpaid' => $tenantId,
        'tenant_due' => $tenantId,
        'tenant_revenue' => $tenantId,
    ]);
    $stats = $counts->fetch() ?: [];
    View::header('Dashboard');
    ?>
    <div class="page-heading"><div><p class="eyebrow">Ringkasan ISP</p><h1>Dashboard billing</h1></div><span class="secure-badge">Tenant terisolasi</span></div>
    <section class="stat-grid">
        <article class="stat-card"><span>Pelanggan aktif</span><strong><?= e($stats['active_customers'] ?? 0) ?></strong><small>Layanan berjalan</small></article>
        <article class="stat-card"><span>Tagihan belum lunas</span><strong><?= e($stats['unpaid_invoices'] ?? 0) ?></strong><small>Perlu ditindaklanjuti</small></article>
        <article class="stat-card"><span>Total piutang</span><strong><?= e(rupiah($stats['outstanding'] ?? 0)) ?></strong><small>Semua tagihan aktif</small></article>
        <article class="stat-card stat-card-accent"><span>Pendapatan bulan ini</span><strong><?= e(rupiah($stats['monthly_revenue'] ?? 0)) ?></strong><small>Pembayaran tercatat</small></article>
    </section>
    <section class="panel welcome-panel"><div><p class="eyebrow">Fondasi aman</p><h2>Siap untuk operasi awal</h2><p>Semua data bisnis difilter dengan identitas ISP yang sedang masuk. Tambahkan paket, pelanggan, lalu terbitkan tagihan pertama.</p></div><div class="quick-actions"><a class="button button-primary" href="/customers">Tambah pelanggan</a><a class="button button-secondary" href="/invoices">Buat tagihan</a></div></section>
    <?php
    View::footer();
    exit;
}

if ($path === '/customers') {
    $plansQuery = $db->prepare("SELECT id, name, speed_label FROM plans WHERE tenant_id = :tenant_id AND status = 'active' ORDER BY name");
    $plansQuery->execute(['tenant_id' => $tenantId]);
    $plans = $plansQuery->fetchAll();
    $customersQuery = $db->prepare(
        'SELECT c.customer_code, c.name, c.phone, c.status, p.name AS plan_name, p.speed_label
         FROM customers c LEFT JOIN plans p ON p.id = c.plan_id
         WHERE c.tenant_id = :tenant_id ORDER BY c.id DESC LIMIT 100'
    );
    $customersQuery->execute(['tenant_id' => $tenantId]);
    View::header('Pelanggan');
    ?>
    <div class="page-heading"><div><p class="eyebrow">Master data</p><h1>Pelanggan</h1></div></div>
    <?php if (Auth::canManageBilling()): ?>
    <section class="panel"><h2>Tambah pelanggan</h2><form method="post" class="form-grid"><?= csrf_field() ?><label>Kode pelanggan<input name="customer_code" maxlength="30" required placeholder="CUST-001"></label><label>Nama lengkap<input name="name" maxlength="120" required></label><label>Nomor WhatsApp<input name="phone" maxlength="30"></label><label>Email<input type="email" name="email" maxlength="190"></label><label>Paket<select name="plan_id"><option value="">Belum ditentukan</option><?php foreach ($plans as $plan): ?><option value="<?= e($plan['id']) ?>"><?= e($plan['name'] . ' · ' . $plan['speed_label']) ?></option><?php endforeach; ?></select></label><label class="field-wide">Alamat<textarea name="address" rows="2"></textarea></label><div class="field-wide"><button class="button button-primary" type="submit">Simpan pelanggan</button></div></form></section>
    <?php endif; ?>
    <section class="panel"><h2>Daftar pelanggan</h2><div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama</th><th>Paket</th><th>WhatsApp</th><th>Status</th></tr></thead><tbody><?php foreach ($customersQuery as $customer): ?><tr><td><strong><?= e($customer['customer_code']) ?></strong></td><td><?= e($customer['name']) ?></td><td><?= e($customer['plan_name'] ?? '—') ?><small><?= e($customer['speed_label'] ?? '') ?></small></td><td><?= e($customer['phone'] ?: '—') ?></td><td><span class="status status-<?= e($customer['status']) ?>"><?= e($customer['status']) ?></span></td></tr><?php endforeach; ?></tbody></table></div></section>
    <?php
    View::footer();
    exit;
}

if ($path === '/plans') {
    $plansQuery = $db->prepare('SELECT code, name, speed_label, price, status FROM plans WHERE tenant_id = :tenant_id ORDER BY id DESC');
    $plansQuery->execute(['tenant_id' => $tenantId]);
    View::header('Paket');
    ?>
    <div class="page-heading"><div><p class="eyebrow">Produk layanan</p><h1>Paket internet</h1></div></div>
    <?php if (Auth::canManageBilling()): ?><section class="panel"><h2>Tambah paket</h2><form method="post" class="form-grid"><?= csrf_field() ?><label>Kode paket<input name="code" maxlength="30" required placeholder="HOME-20"></label><label>Nama paket<input name="name" maxlength="120" required></label><label>Kecepatan<input name="speed_label" maxlength="80" required placeholder="20 Mbps"></label><label>Harga bulanan<input type="number" name="price" min="0" step="1000" required></label><div class="field-wide"><button class="button button-primary" type="submit">Simpan paket</button></div></form></section><?php endif; ?>
    <section class="panel"><h2>Daftar paket</h2><div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama</th><th>Kecepatan</th><th>Harga</th><th>Status</th></tr></thead><tbody><?php foreach ($plansQuery as $plan): ?><tr><td><strong><?= e($plan['code']) ?></strong></td><td><?= e($plan['name']) ?></td><td><?= e($plan['speed_label']) ?></td><td><?= e(rupiah($plan['price'])) ?></td><td><span class="status status-<?= e($plan['status']) ?>"><?= e($plan['status']) ?></span></td></tr><?php endforeach; ?></tbody></table></div></section>
    <?php
    View::footer();
    exit;
}

if ($path === '/invoices') {
    $customersQuery = $db->prepare("SELECT id, customer_code, name FROM customers WHERE tenant_id = :tenant_id AND status = 'active' ORDER BY name");
    $customersQuery->execute(['tenant_id' => $tenantId]);
    $customers = $customersQuery->fetchAll();
    $invoicesQuery = $db->prepare(
        'SELECT i.id, i.invoice_number, i.period_label, i.amount, i.due_date, i.status, c.customer_code, c.name AS customer_name
         FROM invoices i INNER JOIN customers c ON c.id = i.customer_id
         WHERE i.tenant_id = :tenant_id ORDER BY i.id DESC LIMIT 100'
    );
    $invoicesQuery->execute(['tenant_id' => $tenantId]);
    View::header('Tagihan');
    ?>
    <div class="page-heading"><div><p class="eyebrow">Keuangan</p><h1>Tagihan</h1></div></div>
    <?php if (Auth::canManageBilling()): ?><section class="panel"><h2>Terbitkan tagihan</h2><form method="post" class="form-grid"><?= csrf_field() ?><input type="hidden" name="_action" value="create"><label>Pelanggan<select name="customer_id" required><option value="">Pilih pelanggan</option><?php foreach ($customers as $customer): ?><option value="<?= e($customer['id']) ?>"><?= e($customer['customer_code'] . ' · ' . $customer['name']) ?></option><?php endforeach; ?></select></label><label>Periode<input name="period_label" maxlength="40" required placeholder="Agustus 2026"></label><label>Nominal<input type="number" name="amount" min="1" step="1000" required></label><label>Jatuh tempo<input type="date" name="due_date" required></label><div class="field-wide"><button class="button button-primary" type="submit">Terbitkan tagihan</button></div></form></section><?php endif; ?>
    <section class="panel"><h2>Daftar tagihan</h2><div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Pelanggan</th><th>Periode</th><th>Jatuh tempo</th><th>Nominal</th><th>Status</th><th>Aksi</th></tr></thead><tbody><?php foreach ($invoicesQuery as $invoice): $overdue = $invoice['status'] === 'unpaid' && $invoice['due_date'] < date('Y-m-d'); ?><tr><td><strong><?= e($invoice['invoice_number']) ?></strong></td><td><?= e($invoice['customer_code']) ?><small><?= e($invoice['customer_name']) ?></small></td><td><?= e($invoice['period_label']) ?></td><td><?= e($invoice['due_date']) ?></td><td><?= e(rupiah($invoice['amount'])) ?></td><td><span class="status status-<?= $overdue ? 'overdue' : e($invoice['status']) ?>"><?= $overdue ? 'overdue' : e($invoice['status']) ?></span></td><td><?php if ($invoice['status'] === 'unpaid' && Auth::canManageBilling()): ?><form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="pay"><input type="hidden" name="invoice_id" value="<?= e($invoice['id']) ?>"><button class="button button-small" type="submit">Tandai lunas</button></form><?php else: ?>—<?php endif; ?></td></tr><?php endforeach; ?></tbody></table></div></section>
    <?php
    View::footer();
    exit;
}

http_response_code(404);
View::header('Tidak ditemukan');
?>
<section class="panel empty-state"><p class="eyebrow">404</p><h1>Halaman tidak ditemukan</h1><a class="button button-primary" href="/">Kembali ke dashboard</a></section>
<?php View::footer();
