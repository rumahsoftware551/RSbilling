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

if ($path === '/customers/import/template' && $method === 'GET') {
    Auth::requireBillingAccess();
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="template-pelanggan-rsbilling.csv"');
    header('Cache-Control: no-store');
    $output = fopen('php://output', 'wb');
    if ($output === false) {
        throw new RuntimeException('Template CSV tidak dapat dibuat.');
    }
    fwrite($output, "\xEF\xBB\xBF");
    CsvService::writeRow($output, ['customer_code', 'name', 'phone', 'email', 'address', 'plan_code', 'status']);
    CsvService::writeRow($output, ['CUST-001', 'Pelanggan Contoh', '081234567890', 'pelanggan@example.com', 'Alamat pelanggan', '', 'active']);
    fclose($output);
    exit;
}

if ($path === '/customers/import' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $upload = $_FILES['csv_file'] ?? null;
    if (!is_array($upload) || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK
        || !is_string($upload['tmp_name'] ?? null) || !is_string($upload['name'] ?? null)) {
        flash('error', 'Pilih file CSV pelanggan yang valid.');
        redirect('/customers/import');
    }
    $fileSize = (int) ($upload['size'] ?? 0);
    if ($fileSize < 1 || $fileSize > 2 * 1024 * 1024) {
        flash('error', 'Ukuran file CSV harus berada di antara 1 byte dan 2 MB.');
        redirect('/customers/import');
    }
    if (strtolower(pathinfo($upload['name'], PATHINFO_EXTENSION)) !== 'csv'
        || !is_uploaded_file($upload['tmp_name'])) {
        flash('error', 'File wajib berformat CSV dan berasal dari upload yang sah.');
        redirect('/customers/import');
    }

    try {
        $rows = CustomerImportService::parse($upload['tmp_name']);

        $planQuery = $db->prepare(
            "SELECT id, code FROM plans
             WHERE tenant_id = :tenant_id AND status = 'active'"
        );
        $planQuery->execute(['tenant_id' => $tenantId]);
        $planMap = [];
        foreach ($planQuery as $plan) {
            $planMap[strtoupper((string) $plan['code'])] = (int) $plan['id'];
        }

        $candidates = [];
        $seenCodes = [];
        foreach ($rows as $row) {
            $rowNumber = (int) $row['_row'];
            $code = strtoupper($row['customer_code']);
            $name = $row['name'];
            $phone = $row['phone'];
            $email = strtolower($row['email']);
            $address = $row['address'];
            $planCode = strtoupper($row['plan_code']);
            $status = strtolower($row['status'] !== '' ? $row['status'] : 'active');

            if (!preg_match('/^[A-Z0-9._-]{2,30}$/', $code)) {
                throw new InvalidArgumentException('Baris ' . $rowNumber . ': customer_code tidak valid.');
            }
            if ($name === '' || strlen($name) > 120) {
                throw new InvalidArgumentException('Baris ' . $rowNumber . ': nama wajib diisi dan maksimal 120 karakter.');
            }
            if (strlen($phone) > 30 || strlen($address) > 2000) {
                throw new InvalidArgumentException('Baris ' . $rowNumber . ': nomor telepon atau alamat terlalu panjang.');
            }
            if ($email !== '' && (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190)) {
                throw new InvalidArgumentException('Baris ' . $rowNumber . ': email tidak valid.');
            }
            if (!in_array($status, ['active', 'suspended', 'terminated'], true)) {
                throw new InvalidArgumentException('Baris ' . $rowNumber . ': status pelanggan tidak valid.');
            }
            if ($planCode !== '' && !isset($planMap[$planCode])) {
                throw new InvalidArgumentException('Baris ' . $rowNumber . ': plan_code tidak ditemukan atau paket tidak aktif.');
            }
            if (isset($seenCodes[$code])) {
                throw new InvalidArgumentException('Baris ' . $rowNumber . ': customer_code berulang di dalam file.');
            }
            $seenCodes[$code] = true;

            $candidates[] = [
                'tenant_id' => $tenantId,
                'plan_id' => $planCode !== '' ? $planMap[$planCode] : null,
                'customer_code' => $code,
                'name' => $name,
                'phone' => $phone,
                'email' => $email !== '' ? $email : null,
                'address' => $address !== '' ? $address : null,
                'status' => $status,
            ];
        }

        $existingParams = ['tenant_id' => $tenantId];
        $existingPlaceholders = [];
        foreach ($candidates as $index => $candidate) {
            $key = 'code_' . $index;
            $existingPlaceholders[] = ':' . $key;
            $existingParams[$key] = $candidate['customer_code'];
        }
        $existingQuery = $db->prepare(
            'SELECT customer_code FROM customers
             WHERE tenant_id = :tenant_id AND customer_code IN (' . implode(', ', $existingPlaceholders) . ')'
        );
        $existingQuery->execute($existingParams);
        $existingCodes = [];
        foreach ($existingQuery as $customer) {
            $existingCodes[strtoupper((string) $customer['customer_code'])] = true;
        }

        $validated = [];
        $skipped = 0;
        foreach ($candidates as $candidate) {
            if (isset($existingCodes[$candidate['customer_code']])) {
                $skipped++;
                continue;
            }
            $validated[] = $candidate;
        }

        $db->beginTransaction();
        try {
            $insert = $db->prepare(
                'INSERT INTO customers
                    (tenant_id, plan_id, customer_code, name, phone, email, address, status)
                 VALUES
                    (:tenant_id, :plan_id, :customer_code, :name, :phone, :email, :address, :status)'
            );
            foreach ($validated as $customer) {
                $insert->execute($customer);
            }
            $sourceName = preg_replace('/[^A-Za-z0-9._-]/', '_', basename($upload['name'])) ?: 'customers.csv';
            audit_event($db, 'customer.csv_imported', 'customer_batch', null, [
                'created' => count($validated),
                'skipped_existing' => $skipped,
                'source_rows' => count($rows),
                'file_name' => substr($sourceName, 0, 120),
            ]);
            $db->commit();
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $exception;
        }

        flash('success', sprintf(
            'Import selesai: %d pelanggan dibuat dan %d kode yang sudah ada dilewati.',
            count($validated),
            $skipped
        ));
        redirect('/customers');
    } catch (InvalidArgumentException $exception) {
        flash('error', $exception->getMessage());
        redirect('/customers/import');
    } catch (PDOException $exception) {
        if ($exception->getCode() === '23000') {
            flash('error', 'Data pelanggan berubah saat import. Muat ulang dan ulangi import.');
            redirect('/customers/import');
        }
        throw $exception;
    }
}

if ($path === '/customers/import' && $method === 'GET') {
    Auth::requireBillingAccess();
    $planQuery = $db->prepare(
        "SELECT code, name, speed_label FROM plans
         WHERE tenant_id = :tenant_id AND status = 'active' ORDER BY code"
    );
    $planQuery->execute(['tenant_id' => $tenantId]);
    $activePlans = $planQuery->fetchAll();
    View::header('Import pelanggan');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Migrasi data</p><h1>Import pelanggan CSV</h1></div>
        <a class="button button-secondary" href="/customers">Kembali</a>
    </div>
    <section class="account-grid import-grid">
        <article class="panel">
            <h2>Upload file CSV</h2>
            <p class="muted">Import bersifat atomik: apabila satu baris tidak valid, tidak ada pelanggan baru yang disimpan. Kode pelanggan yang sudah tersedia pada ISP ini akan dilewati.</p>
            <form method="post" enctype="multipart/form-data" class="stack-form">
                <?= csrf_field() ?>
                <label>File pelanggan
                    <input type="file" name="csv_file" accept=".csv,text/csv" required>
                </label>
                <small class="muted">Maksimal 2 MB dan 1.000 baris. Pemisah koma atau titik koma didukung.</small>
                <button class="button button-primary" type="submit">Validasi dan import</button>
            </form>
        </article>
        <article class="panel">
            <div class="section-heading"><div><h2>Format yang didukung</h2><p class="muted">Gunakan template agar nama kolom sesuai.</p></div><a class="button button-link" href="/customers/import/template">Unduh template</a></div>
            <div class="table-wrap"><table><thead><tr><th>Kolom</th><th>Ketentuan</th></tr></thead><tbody>
                <tr><td><code>customer_code</code></td><td>Wajib, unik, 2–30 karakter</td></tr>
                <tr><td><code>name</code></td><td>Wajib, maksimal 120 karakter</td></tr>
                <tr><td><code>phone, email, address</code></td><td>Opsional</td></tr>
                <tr><td><code>plan_code</code></td><td>Opsional, harus paket aktif pada ISP ini</td></tr>
                <tr><td><code>status</code></td><td>active, suspended, atau terminated</td></tr>
            </tbody></table></div>
        </article>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Kode paket aktif</h2><p class="muted">Nilai yang dapat dipakai pada kolom plan_code.</p></div></div>
        <div class="table-wrap"><table><thead><tr><th>Kode</th><th>Paket</th><th>Kecepatan</th></tr></thead><tbody>
            <?php if ($activePlans === []): ?><tr><td colspan="3" class="muted">Belum ada paket aktif. plan_code harus dikosongkan.</td></tr><?php endif; ?>
            <?php foreach ($activePlans as $plan): ?><tr><td><strong><?= e($plan['code']) ?></strong></td><td><?= e($plan['name']) ?></td><td><?= e($plan['speed_label']) ?></td></tr><?php endforeach; ?>
        </tbody></table></div>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/customers' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $action = input('_action', 'create');
    if (!in_array($action, ['create', 'update', 'archive'], true)) {
        flash('error', 'Aksi pelanggan tidak dikenali.');
        redirect('/customers');
    }

    if ($action === 'archive') {
        $customerId = filter_var(input('customer_id'), FILTER_VALIDATE_INT);
        if (!$customerId) {
            flash('error', 'Pelanggan tidak valid.');
            redirect('/customers');
        }

        $db->beginTransaction();
        try {
            $target = $db->prepare(
                'SELECT id, customer_code, status FROM customers
                 WHERE id = :id AND tenant_id = :tenant_id FOR UPDATE'
            );
            $target->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
            $customer = $target->fetch();
            if (!$customer) {
                throw new DomainException('Pelanggan tidak ditemukan pada ISP ini.');
            }
            if ($customer['status'] === 'terminated') {
                throw new DomainException('Pelanggan tersebut sudah diarsipkan.');
            }

            $update = $db->prepare(
                "UPDATE customers SET status = 'terminated'
                 WHERE id = :id AND tenant_id = :tenant_id"
            );
            $update->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
            audit_event($db, 'customer.archived', 'customer', (int) $customerId, [
                'code' => $customer['customer_code'],
                'previous_status' => $customer['status'],
            ]);
            $db->commit();
            flash('success', 'Pelanggan berhasil diarsipkan. Invoice dan pembayaran lama tetap tersimpan.');
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
        redirect('/customers');
    }

    $customerId = filter_var(input('customer_id'), FILTER_VALIDATE_INT);
    $code = strtoupper(input('customer_code'));
    $name = input('name');
    $phone = input('phone');
    $email = input('email');
    $address = input('address');
    $planId = filter_var(input('plan_id'), FILTER_VALIDATE_INT) ?: null;
    $status = input('status', 'active');

    if (!preg_match('/^[A-Z0-9._-]{2,30}$/', $code) || $name === '' || strlen($name) > 120) {
        flash('error', 'Kode atau nama pelanggan tidak valid.');
        redirect('/customers');
    }
    if ($email !== '' && (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 190)) {
        flash('error', 'Format email pelanggan tidak valid.');
        redirect('/customers');
    }
    if ($action === 'update' && (!$customerId || !in_array($status, ['active', 'suspended', 'terminated'], true))) {
        flash('error', 'Status atau ID pelanggan tidak valid.');
        redirect('/customers');
    }
    if ($planId !== null) {
        $planSql = $action === 'update'
            ? 'SELECT id FROM plans WHERE id = :id AND tenant_id = :tenant_id'
            : 'SELECT id FROM plans WHERE id = :id AND tenant_id = :tenant_id AND status = \'active\'';
        $planCheck = $db->prepare($planSql);
        $planCheck->execute(['id' => $planId, 'tenant_id' => $tenantId]);
        if (!$planCheck->fetchColumn()) {
            flash('error', 'Paket tidak ditemukan pada ISP ini.');
            redirect('/customers');
        }
    }

    try {
        if ($action === 'update') {
            $target = $db->prepare('SELECT id FROM customers WHERE id = :id AND tenant_id = :tenant_id');
            $target->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
            if (!$target->fetchColumn()) {
                flash('error', 'Pelanggan tidak ditemukan pada ISP ini.');
                redirect('/customers');
            }
            $update = $db->prepare(
                'UPDATE customers
                 SET plan_id = :plan_id, customer_code = :customer_code, name = :name,
                     phone = :phone, email = :email, address = :address, status = :status
                 WHERE id = :id AND tenant_id = :tenant_id'
            );
            $update->execute([
                'plan_id' => $planId,
                'customer_code' => $code,
                'name' => $name,
                'phone' => substr($phone, 0, 30),
                'email' => $email !== '' ? $email : null,
                'address' => $address !== '' ? $address : null,
                'status' => $status,
                'id' => $customerId,
                'tenant_id' => $tenantId,
            ]);
            audit_event($db, 'customer.updated', 'customer', (int) $customerId, [
                'code' => $code,
                'status' => $status,
            ]);
            flash('success', 'Data pelanggan berhasil diperbarui.');
            redirect('/customers');
        }

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
    $action = input('_action', 'create');
    if (!in_array($action, ['create', 'update', 'archive'], true)) {
        flash('error', 'Aksi paket tidak dikenali.');
        redirect('/plans');
    }

    if ($action === 'archive') {
        $planId = filter_var(input('plan_id'), FILTER_VALIDATE_INT);
        if (!$planId) {
            flash('error', 'Paket tidak valid.');
            redirect('/plans');
        }

        $db->beginTransaction();
        try {
            $target = $db->prepare(
                'SELECT id, code, status FROM plans
                 WHERE id = :id AND tenant_id = :tenant_id FOR UPDATE'
            );
            $target->execute(['id' => $planId, 'tenant_id' => $tenantId]);
            $plan = $target->fetch();
            if (!$plan) {
                throw new DomainException('Paket tidak ditemukan pada ISP ini.');
            }
            if ($plan['status'] === 'inactive') {
                throw new DomainException('Paket tersebut sudah nonaktif atau diarsipkan.');
            }

            $update = $db->prepare(
                "UPDATE plans SET status = 'inactive'
                 WHERE id = :id AND tenant_id = :tenant_id"
            );
            $update->execute(['id' => $planId, 'tenant_id' => $tenantId]);
            audit_event($db, 'plan.archived', 'plan', (int) $planId, ['code' => $plan['code']]);
            $db->commit();
            flash('success', 'Paket berhasil diarsipkan. Pelanggan dan histori tagihan tidak dihapus.');
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
        redirect('/plans');
    }

    $planId = filter_var(input('plan_id'), FILTER_VALIDATE_INT);
    $code = strtoupper(input('code'));
    $name = input('name');
    $speed = input('speed_label');
    $price = filter_var(input('price'), FILTER_VALIDATE_FLOAT);
    $status = input('status', 'active');
    if (!preg_match('/^[A-Z0-9._-]{2,30}$/', $code) || $name === '' || $speed === ''
        || $price === false || $price < 0 || $price > 9999999999999.99) {
        flash('error', 'Data paket belum valid.');
        redirect('/plans');
    }
    if ($action === 'update' && (!$planId || !in_array($status, ['active', 'inactive'], true))) {
        flash('error', 'Status atau ID paket tidak valid.');
        redirect('/plans');
    }
    try {
        if ($action === 'update') {
            $target = $db->prepare('SELECT id FROM plans WHERE id = :id AND tenant_id = :tenant_id');
            $target->execute(['id' => $planId, 'tenant_id' => $tenantId]);
            if (!$target->fetchColumn()) {
                flash('error', 'Paket tidak ditemukan pada ISP ini.');
                redirect('/plans');
            }
            $update = $db->prepare(
                'UPDATE plans SET code = :code, name = :name, speed_label = :speed_label,
                    price = :price, status = :status
                 WHERE id = :id AND tenant_id = :tenant_id'
            );
            $update->execute([
                'code' => $code,
                'name' => substr($name, 0, 120),
                'speed_label' => substr($speed, 0, 80),
                'price' => $price,
                'status' => $status,
                'id' => $planId,
                'tenant_id' => $tenantId,
            ]);
            audit_event($db, 'plan.updated', 'plan', (int) $planId, [
                'code' => $code,
                'status' => $status,
            ]);
            flash('success', 'Paket internet berhasil diperbarui.');
            redirect('/plans');
        }

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

if ($path === '/notifications' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $action = input('_action');
    if (!in_array($action, ['enqueue', 'cancel', 'retry'], true)) {
        flash('error', 'Aksi notifikasi tidak dikenali.');
        redirect('/notifications');
    }

    if ($action === 'enqueue') {
        $invoiceId = filter_var(input('invoice_id'), FILTER_VALIDATE_INT);
        $channel = input('channel');
        if (!$invoiceId) {
            flash('error', 'Invoice untuk notifikasi tidak valid.');
            redirect('/invoices');
        }

        $db->beginTransaction();
        try {
            $result = NotificationService::enqueueInvoice(
                $db,
                $tenantId,
                (int) Auth::user()['id'],
                (int) $invoiceId,
                $channel
            );
            if ($result['created']) {
                audit_event($db, 'notification.queued', 'notification', (int) $result['id'], [
                    'invoice_id' => (int) $invoiceId,
                    'channel' => $channel,
                    'template' => $result['template'],
                ]);
            }
            $db->commit();
            flash(
                'success',
                $result['created']
                    ? 'Pengingat berhasil dimasukkan ke antrean internal.'
                    : 'Pengingat identik sudah tersedia dengan status ' . $result['status'] . '.'
            );
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            if ($exception instanceof DomainException || $exception instanceof InvalidArgumentException) {
                flash('error', $exception->getMessage());
            } else {
                throw $exception;
            }
        }
        redirect('/invoices/view?id=' . $invoiceId);
    }

    $notificationId = filter_var(input('notification_id'), FILTER_VALIDATE_INT);
    if (!$notificationId) {
        flash('error', 'Notifikasi tidak valid.');
        redirect('/notifications');
    }
    $db->beginTransaction();
    try {
        if ($action === 'cancel') {
            NotificationService::cancel($db, $tenantId, (int) $notificationId);
            $auditAction = 'notification.cancelled';
            $message = 'Notifikasi berhasil dibatalkan.';
        } else {
            NotificationService::retry($db, $tenantId, (int) $notificationId);
            $auditAction = 'notification.retried';
            $message = 'Notifikasi berhasil dimasukkan ulang ke antrean.';
        }
        audit_event($db, $auditAction, 'notification', (int) $notificationId);
        $db->commit();
        flash('success', $message);
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
    redirect('/notifications');
}

if ($path === '/notifications' && $method === 'GET') {
    Auth::requireBillingAccess();
    $statusFilter = query_input('status');
    $channelFilter = query_input('channel');
    if (!in_array($statusFilter, ['', 'pending', 'processing', 'sent', 'failed', 'cancelled'], true)) {
        $statusFilter = '';
    }
    if (!in_array($channelFilter, ['', 'whatsapp', 'email'], true)) {
        $channelFilter = '';
    }

    $statusCounts = ['pending' => 0, 'processing' => 0, 'sent' => 0, 'failed' => 0, 'cancelled' => 0];
    $summaryQuery = $db->prepare(
        'SELECT status, COUNT(*) AS total FROM notification_outbox
         WHERE tenant_id = :tenant_id GROUP BY status'
    );
    $summaryQuery->execute(['tenant_id' => $tenantId]);
    foreach ($summaryQuery as $summary) {
        $statusCounts[(string) $summary['status']] = (int) $summary['total'];
    }

    $where = ['n.tenant_id = :tenant_id'];
    $params = ['tenant_id' => $tenantId];
    if ($statusFilter !== '') {
        $where[] = 'n.status = :status';
        $params['status'] = $statusFilter;
    }
    if ($channelFilter !== '') {
        $where[] = 'n.channel = :channel';
        $params['channel'] = $channelFilter;
    }
    $whereSql = implode(' AND ', $where);
    $countQuery = $db->prepare('SELECT COUNT(*) FROM notification_outbox n WHERE ' . $whereSql);
    $countQuery->execute($params);
    $pagination = new Pagination((int) $countQuery->fetchColumn(), requested_page());

    $queueQuery = $db->prepare(
        'SELECT n.id, n.channel, n.recipient, n.template, n.subject, n.message, n.status,
                n.attempts, n.max_attempts, n.available_at, n.sent_at, n.last_error, n.created_at,
                i.id AS invoice_id, i.invoice_number, c.customer_code, c.name AS customer_name,
                u.name AS created_by_name
         FROM notification_outbox n
         LEFT JOIN invoices i ON i.id = n.invoice_id AND i.tenant_id = n.tenant_id
         INNER JOIN customers c ON c.id = n.customer_id AND c.tenant_id = n.tenant_id
         INNER JOIN users u ON u.id = n.created_by
         WHERE ' . $whereSql . ' ORDER BY n.id DESC LIMIT :limit OFFSET :offset'
    );
    foreach ($params as $key => $value) {
        $queueQuery->bindValue(':' . $key, $value);
    }
    $queueQuery->bindValue(':limit', $pagination->perPage, PDO::PARAM_INT);
    $queueQuery->bindValue(':offset', $pagination->offset(), PDO::PARAM_INT);
    $queueQuery->execute();
    $notifications = $queueQuery->fetchAll();

    View::header('Antrean Notifikasi');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Komunikasi pelanggan</p><h1>Antrean notifikasi</h1></div>
        <span class="secure-badge">Tenant-safe outbox</span>
    </div>
    <div class="notice">Pengiriman provider belum diaktifkan. Pesan berstatus pending tersimpan aman dan tidak akan dikirim sampai adapter WhatsApp/email serta worker dikonfigurasi.</div>
    <section class="stat-grid">
        <article class="stat-card"><span>Menunggu</span><strong><?= e($statusCounts['pending']) ?></strong><small>Siap diproses worker</small></article>
        <article class="stat-card"><span>Terkirim</span><strong><?= e($statusCounts['sent']) ?></strong><small>Konfirmasi provider</small></article>
        <article class="stat-card"><span>Gagal</span><strong><?= e($statusCounts['failed']) ?></strong><small>Dapat dicoba ulang</small></article>
        <article class="stat-card"><span>Dibatalkan</span><strong><?= e($statusCounts['cancelled']) ?></strong><small>Tidak akan dikirim</small></article>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Daftar pesan</h2><p class="muted">Pesan dibuat dari detail invoice dan dilindungi kunci idempotensi.</p></div></div>
        <form method="get" class="report-filter">
            <label>Status<select name="status"><option value="">Semua status</option><?php foreach (['pending', 'processing', 'sent', 'failed', 'cancelled'] as $status): ?><option value="<?= e($status) ?>"<?= $statusFilter === $status ? ' selected' : '' ?>><?= e($status) ?></option><?php endforeach; ?></select></label>
            <label>Kanal<select name="channel"><option value="">Semua kanal</option><option value="whatsapp"<?= $channelFilter === 'whatsapp' ? ' selected' : '' ?>>WhatsApp</option><option value="email"<?= $channelFilter === 'email' ? ' selected' : '' ?>>Email</option></select></label>
            <button class="button button-primary" type="submit">Terapkan</button>
            <a class="button button-secondary" href="/notifications">Reset</a>
        </form>
        <div class="table-wrap">
            <table><thead><tr><th>Dibuat</th><th>Pelanggan</th><th>Invoice</th><th>Kanal</th><th>Tujuan</th><th>Status</th><th>Pesan</th><th>Aksi</th></tr></thead><tbody>
                <?php if ($notifications === []): ?><tr><td colspan="8" class="muted">Belum ada notifikasi yang sesuai.</td></tr><?php endif; ?>
                <?php foreach ($notifications as $notification): ?>
                    <tr>
                        <td><?= e($notification['created_at']) ?><small><?= e($notification['created_by_name']) ?></small></td>
                        <td><?= e($notification['customer_code']) ?><small><?= e($notification['customer_name']) ?></small></td>
                        <td><?php if ($notification['invoice_id']): ?><a class="table-link" href="/invoices/view?id=<?= e($notification['invoice_id']) ?>"><?= e($notification['invoice_number']) ?></a><?php else: ?>—<?php endif; ?></td>
                        <td><span class="role-badge"><?= e($notification['channel']) ?></span></td>
                        <td><?= e($notification['recipient']) ?></td>
                        <td><span class="status status-<?= e($notification['status']) ?>"><?= e($notification['status']) ?></span><small>Percobaan <?= e($notification['attempts']) ?>/<?= e($notification['max_attempts']) ?></small></td>
                        <td><details class="notification-preview"><summary>Lihat pesan</summary><?php if ($notification['subject']): ?><strong><?= e($notification['subject']) ?></strong><?php endif; ?><pre><?= e($notification['message']) ?></pre><?php if ($notification['last_error']): ?><small class="error-text"><?= e($notification['last_error']) ?></small><?php endif; ?></details></td>
                        <td><div class="action-group">
                            <?php if (in_array($notification['status'], ['failed', 'cancelled'], true)): ?><form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="retry"><input type="hidden" name="notification_id" value="<?= e($notification['id']) ?>"><button class="button button-link" type="submit">Ulangi</button></form><?php endif; ?>
                            <?php if (in_array($notification['status'], ['pending', 'failed'], true)): ?><form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="cancel"><input type="hidden" name="notification_id" value="<?= e($notification['id']) ?>"><button class="button button-danger" type="submit">Batalkan</button></form><?php endif; ?>
                        </div></td>
                    </tr>
                <?php endforeach; ?>
            </tbody></table>
        </div>
        <?php View::pagination($pagination); ?>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/reconciliation/template' && $method === 'GET') {
    Auth::requireBillingAccess();
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="template-rekonsiliasi-rsbilling.csv"');
    header('Cache-Control: no-store');
    $output = fopen('php://output', 'wb');
    if ($output === false) {
        throw new RuntimeException('Template rekonsiliasi tidak dapat dibuat.');
    }
    fwrite($output, "\xEF\xBB\xBF");
    CsvService::writeRow($output, [
        'external_reference', 'invoice_number', 'amount', 'paid_at', 'method', 'payer_name',
    ]);
    CsvService::writeRow($output, [
        'TRX-000001', 'INV-GANTI-SESUAI-DATA', '150000.00', date('Y-m-d H:i:s'), 'bank_transfer', 'Nama Pembayar',
    ]);
    fclose($output);
    exit;
}

if ($path === '/reconciliation/import' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $upload = $_FILES['csv_file'] ?? null;
    if (!is_array($upload) || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK
        || !is_string($upload['tmp_name'] ?? null) || !is_string($upload['name'] ?? null)) {
        flash('error', 'Pilih file rekonsiliasi CSV yang valid.');
        redirect('/reconciliation');
    }
    $fileSize = (int) ($upload['size'] ?? 0);
    if ($fileSize < 1 || $fileSize > 2 * 1024 * 1024) {
        flash('error', 'Ukuran file rekonsiliasi harus berada di antara 1 byte dan 2 MB.');
        redirect('/reconciliation');
    }
    if (strtolower(pathinfo($upload['name'], PATHINFO_EXTENSION)) !== 'csv'
        || !is_uploaded_file($upload['tmp_name'])) {
        flash('error', 'File rekonsiliasi wajib berformat CSV dan berasal dari upload yang sah.');
        redirect('/reconciliation');
    }

    try {
        $rows = PaymentReconciliationService::parseCsv($upload['tmp_name']);
        $batch = bin2hex(random_bytes(16));
        $sourceName = preg_replace('/[^A-Za-z0-9._-]/', '_', basename($upload['name'])) ?: 'reconciliation.csv';
        $sourceName = substr($sourceName, 0, 120);
        $counts = ['matched' => 0, 'unmatched' => 0, 'duplicate' => 0];

        $db->beginTransaction();
        try {
            $preparedRows = PaymentReconciliationService::prepareRows($db, $tenantId, $rows);
            $insert = $db->prepare(
                'INSERT INTO payment_reconciliations
                    (tenant_id, invoice_id, external_reference, invoice_number, amount, paid_at,
                     method, payer_name, match_status, match_reason, import_batch, source_file, created_by)
                 VALUES
                    (:tenant_id, :invoice_id, :external_reference, :invoice_number, :amount, :paid_at,
                     :method, :payer_name, :match_status, :match_reason, :import_batch, :source_file, :created_by)
                 ON DUPLICATE KEY UPDATE id = id'
            );
            foreach ($preparedRows as $row) {
                $insert->execute([
                    'tenant_id' => $tenantId,
                    'invoice_id' => $row['invoice_id'],
                    'external_reference' => $row['external_reference'],
                    'invoice_number' => $row['invoice_number'],
                    'amount' => $row['amount'],
                    'paid_at' => $row['paid_at'],
                    'method' => $row['method'],
                    'payer_name' => $row['payer_name'],
                    'match_status' => $row['match_status'],
                    'match_reason' => $row['match_reason'],
                    'import_batch' => $batch,
                    'source_file' => $sourceName,
                    'created_by' => (int) Auth::user()['id'],
                ]);
                if ($insert->rowCount() === 1) {
                    $counts[$row['match_status']]++;
                } else {
                    $counts['duplicate']++;
                }
            }
            audit_event($db, 'reconciliation.imported', 'reconciliation_batch', null, [
                'batch' => $batch,
                'file_name' => $sourceName,
                'source_rows' => count($rows),
                'matched' => $counts['matched'],
                'unmatched' => $counts['unmatched'],
                'duplicate' => $counts['duplicate'],
            ]);
            $db->commit();
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $exception;
        }

        flash('success', sprintf(
            'Import selesai: %d cocok, %d perlu pemeriksaan, dan %d referensi duplikat dilewati.',
            $counts['matched'],
            $counts['unmatched'],
            $counts['duplicate']
        ));
    } catch (InvalidArgumentException $exception) {
        flash('error', $exception->getMessage());
    }
    redirect('/reconciliation');
}

if ($path === '/reconciliation' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $action = input('_action');
    $reconciliationId = filter_var(input('reconciliation_id'), FILTER_VALIDATE_INT);
    if (!in_array($action, ['post', 'rematch', 'ignore'], true) || !$reconciliationId) {
        flash('error', 'Aksi atau transaksi rekonsiliasi tidak valid.');
        redirect('/reconciliation');
    }

    $db->beginTransaction();
    try {
        if ($action === 'post') {
            $result = PaymentReconciliationService::post(
                $db,
                $tenantId,
                (int) Auth::user()['id'],
                (int) $reconciliationId
            );
            $invalidatedMatches = PaymentReconciliationService::invalidateInvoiceMatches(
                $db,
                $tenantId,
                $result['invoice_id']
            );
            $cancelledNotifications = NotificationService::cancelInvoiceNotifications(
                $db,
                $tenantId,
                $result['invoice_id']
            );
            audit_event($db, 'payment.reconciled', 'payment', $result['payment_id'], [
                'reconciliation_id' => (int) $reconciliationId,
                'invoice_id' => $result['invoice_id'],
                'reference' => $result['reference'],
                'method' => $result['method'],
                'invalidated_matches' => $invalidatedMatches,
                'cancelled_notifications' => $cancelledNotifications,
            ]);
            $message = 'Pembayaran berhasil diposting dan invoice ditandai lunas.';
        } elseif ($action === 'rematch') {
            $match = PaymentReconciliationService::rematch($db, $tenantId, (int) $reconciliationId);
            audit_event($db, 'reconciliation.rematched', 'payment_reconciliation', (int) $reconciliationId, [
                'status' => $match['match_status'],
                'reason' => $match['match_reason'],
                'invoice_id' => $match['invoice_id'],
            ]);
            $message = $match['match_status'] === 'matched'
                ? 'Transaksi sekarang cocok dan siap diposting.'
                : 'Transaksi masih belum cocok. Periksa nomor invoice dan nominal.';
        } else {
            PaymentReconciliationService::ignore($db, $tenantId, (int) $reconciliationId);
            audit_event($db, 'reconciliation.ignored', 'payment_reconciliation', (int) $reconciliationId);
            $message = 'Transaksi rekonsiliasi ditandai diabaikan.';
        }
        $db->commit();
        flash('success', $message);
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
    redirect('/reconciliation');
}

if ($path === '/reconciliation' && $method === 'GET') {
    Auth::requireBillingAccess();
    $statusFilter = query_input('status');
    if (!in_array($statusFilter, ['', 'matched', 'unmatched', 'posted', 'ignored'], true)) {
        $statusFilter = '';
    }

    $statusCounts = ['matched' => 0, 'unmatched' => 0, 'posted' => 0, 'ignored' => 0];
    $summaryQuery = $db->prepare(
        'SELECT match_status, COUNT(*) AS total FROM payment_reconciliations
         WHERE tenant_id = :tenant_id GROUP BY match_status'
    );
    $summaryQuery->execute(['tenant_id' => $tenantId]);
    foreach ($summaryQuery as $summary) {
        $statusCounts[(string) $summary['match_status']] = (int) $summary['total'];
    }

    $where = ['r.tenant_id = :tenant_id'];
    $params = ['tenant_id' => $tenantId];
    if ($statusFilter !== '') {
        $where[] = 'r.match_status = :status';
        $params['status'] = $statusFilter;
    }
    $whereSql = implode(' AND ', $where);
    $countQuery = $db->prepare('SELECT COUNT(*) FROM payment_reconciliations r WHERE ' . $whereSql);
    $countQuery->execute($params);
    $pagination = new Pagination((int) $countQuery->fetchColumn(), requested_page());
    $itemsQuery = $db->prepare(
        'SELECT r.id, r.invoice_id, r.payment_id, r.external_reference, r.invoice_number,
                r.amount, r.paid_at, r.method, r.payer_name, r.match_status, r.match_reason,
                r.source_file, r.created_at, i.status AS invoice_status, u.name AS created_by_name
         FROM payment_reconciliations r
         LEFT JOIN invoices i ON i.id = r.invoice_id AND i.tenant_id = r.tenant_id
         INNER JOIN users u ON u.id = r.created_by
         WHERE ' . $whereSql . ' ORDER BY r.id DESC LIMIT :limit OFFSET :offset'
    );
    foreach ($params as $key => $value) {
        $itemsQuery->bindValue(':' . $key, $value);
    }
    $itemsQuery->bindValue(':limit', $pagination->perPage, PDO::PARAM_INT);
    $itemsQuery->bindValue(':offset', $pagination->offset(), PDO::PARAM_INT);
    $itemsQuery->execute();
    $items = $itemsQuery->fetchAll();

    $reasonLabels = [
        'exact_match' => 'Nomor dan nominal cocok',
        'invoice_not_found' => 'Invoice tidak ditemukan',
        'invoice_not_payable' => 'Invoice bukan belum lunas',
        'amount_mismatch' => 'Nominal berbeda',
    ];
    View::header('Rekonsiliasi Pembayaran');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Kontrol penerimaan</p><h1>Rekonsiliasi pembayaran</h1></div>
        <a class="button button-secondary" href="/reconciliation/template">Unduh template CSV</a>
    </div>
    <section class="stat-grid">
        <article class="stat-card"><span>Cocok</span><strong><?= e($statusCounts['matched']) ?></strong><small>Siap diposting</small></article>
        <article class="stat-card"><span>Perlu diperiksa</span><strong><?= e($statusCounts['unmatched']) ?></strong><small>Tidak mengubah kas</small></article>
        <article class="stat-card"><span>Sudah diposting</span><strong><?= e($statusCounts['posted']) ?></strong><small>Invoice dilunasi</small></article>
        <article class="stat-card"><span>Diabaikan</span><strong><?= e($statusCounts['ignored']) ?></strong><small>Tersimpan untuk audit</small></article>
    </section>
    <section class="account-grid">
        <article class="panel">
            <h2>Import mutasi CSV</h2>
            <p class="muted">Maksimal 2 MB dan 1.000 transaksi. Import hanya membuat staging; pembayaran baru tercatat setelah tombol Posting dipilih.</p>
            <form method="post" action="/reconciliation/import" enctype="multipart/form-data" class="stack-form">
                <?= csrf_field() ?>
                <label>File mutasi<input type="file" name="csv_file" accept=".csv,text/csv" required></label>
                <button class="button button-primary" type="submit">Validasi dan import</button>
            </form>
        </article>
        <article class="panel">
            <h2>Aturan exact-match</h2>
            <dl class="detail-list">
                <div><dt>Invoice</dt><dd>Nomor harus sama persis dan berada pada ISP aktif</dd></div>
                <div><dt>Nominal</dt><dd>Harus sama dengan total invoice; tanpa pemisah ribuan</dd></div>
                <div><dt>Referensi</dt><dd>Unik untuk kombinasi ISP dan metode</dd></div>
                <div><dt>Format tanggal</dt><dd>YYYY-MM-DD atau YYYY-MM-DD HH:MM:SS</dd></div>
            </dl>
        </article>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Staging transaksi</h2><p class="muted">Periksa transaksi cocok sebelum memposting pembayaran.</p></div></div>
        <form method="get" class="compact-form form-grid reconciliation-filter">
            <label>Status<select name="status"><option value="">Semua status</option><?php foreach (['matched', 'unmatched', 'posted', 'ignored'] as $status): ?><option value="<?= e($status) ?>"<?= $statusFilter === $status ? ' selected' : '' ?>><?= e($status) ?></option><?php endforeach; ?></select></label>
            <div class="form-action"><button class="button button-primary" type="submit">Terapkan</button><a class="button button-secondary" href="/reconciliation">Reset</a></div>
        </form>
        <div class="table-wrap">
            <table><thead><tr><th>Waktu bayar</th><th>Referensi</th><th>Invoice</th><th>Nominal</th><th>Metode/pembayar</th><th>Hasil</th><th>Sumber</th><th>Aksi</th></tr></thead><tbody>
                <?php if ($items === []): ?><tr><td colspan="8" class="muted">Belum ada transaksi rekonsiliasi.</td></tr><?php endif; ?>
                <?php foreach ($items as $item): ?>
                    <tr>
                        <td><?= e($item['paid_at']) ?><small>Import <?= e($item['created_at']) ?></small></td>
                        <td><strong><?= e($item['external_reference']) ?></strong></td>
                        <td><?php if ($item['invoice_id']): ?><a class="table-link" href="/invoices/view?id=<?= e($item['invoice_id']) ?>"><?= e($item['invoice_number']) ?></a><small><?= e($item['invoice_status'] ?: '—') ?></small><?php else: ?><?= e($item['invoice_number']) ?><?php endif; ?></td>
                        <td><?= e(rupiah($item['amount'])) ?></td>
                        <td><?= e($item['method']) ?><small><?= e($item['payer_name'] ?: '—') ?></small></td>
                        <td><span class="status status-<?= e($item['match_status']) ?>"><?= e($item['match_status']) ?></span><small><?= e($reasonLabels[$item['match_reason']] ?? $item['match_reason']) ?></small></td>
                        <td><?= e($item['source_file']) ?><small><?= e($item['created_by_name']) ?></small></td>
                        <td><div class="action-group">
                            <?php if ($item['match_status'] === 'matched'): ?><form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="post"><input type="hidden" name="reconciliation_id" value="<?= e($item['id']) ?>"><button class="button button-small" type="submit">Posting</button></form><?php endif; ?>
                            <?php if ($item['match_status'] === 'unmatched'): ?><form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="rematch"><input type="hidden" name="reconciliation_id" value="<?= e($item['id']) ?>"><button class="button button-link" type="submit">Cocokkan ulang</button></form><?php endif; ?>
                            <?php if (in_array($item['match_status'], ['matched', 'unmatched'], true)): ?><form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="ignore"><input type="hidden" name="reconciliation_id" value="<?= e($item['id']) ?>"><button class="button button-danger" type="submit">Abaikan</button></form><?php endif; ?>
                            <?php if ($item['match_status'] === 'posted'): ?><span class="muted">Payment #<?= e($item['payment_id']) ?></span><?php endif; ?>
                        </div></td>
                    </tr>
                <?php endforeach; ?>
            </tbody></table>
        </div>
        <?php View::pagination($pagination); ?>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/invoices' && $method === 'POST') {
    Auth::requireBillingAccess();
    verify_csrf();
    $action = input('_action', 'create');
    if (!in_array($action, ['create', 'pay', 'cancel', 'penalty', 'generate'], true)) {
        flash('error', 'Aksi invoice tidak dikenali.');
        redirect('/invoices');
    }

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
            $invalidatedMatches = PaymentReconciliationService::invalidateInvoiceMatches(
                $db,
                $tenantId,
                (int) $invoiceId
            );
            $cancelledNotifications = NotificationService::cancelInvoiceNotifications($db, $tenantId, (int) $invoiceId);
            audit_event($db, 'invoice.paid', 'invoice', (int) $invoiceId, [
                'invalidated_matches' => $invalidatedMatches,
                'cancelled_notifications' => $cancelledNotifications,
            ]);
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

    if ($action === 'cancel') {
        $invoiceId = filter_var(input('invoice_id'), FILTER_VALIDATE_INT);
        if (!$invoiceId) {
            flash('error', 'Tagihan tidak valid.');
            redirect('/invoices');
        }
        $db->beginTransaction();
        try {
            $invoiceQuery = $db->prepare(
                "SELECT id, status FROM invoices
                 WHERE id = :id AND tenant_id = :tenant_id FOR UPDATE"
            );
            $invoiceQuery->execute(['id' => $invoiceId, 'tenant_id' => $tenantId]);
            $invoice = $invoiceQuery->fetch();
            if (!$invoice || $invoice['status'] !== 'unpaid') {
                throw new DomainException('Hanya tagihan belum lunas yang dapat dibatalkan.');
            }
            $db->prepare(
                "UPDATE invoices SET status = 'cancelled'
                 WHERE id = :id AND tenant_id = :tenant_id"
            )->execute(['id' => $invoiceId, 'tenant_id' => $tenantId]);
            $invalidatedMatches = PaymentReconciliationService::invalidateInvoiceMatches(
                $db,
                $tenantId,
                (int) $invoiceId
            );
            $cancelledNotifications = NotificationService::cancelInvoiceNotifications($db, $tenantId, (int) $invoiceId);
            audit_event($db, 'invoice.cancelled', 'invoice', (int) $invoiceId, [
                'invalidated_matches' => $invalidatedMatches,
                'cancelled_notifications' => $cancelledNotifications,
            ]);
            $db->commit();
            flash('success', 'Tagihan berhasil dibatalkan.');
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
        redirect('/invoices');
    }

    if ($action === 'penalty') {
        $invoiceId = filter_var(input('invoice_id'), FILTER_VALIDATE_INT);
        $penaltyAmount = filter_var(input('penalty_amount'), FILTER_VALIDATE_FLOAT);
        if (!$invoiceId || $penaltyAmount === false || $penaltyAmount < 0) {
            flash('error', 'Invoice atau nominal denda tidak valid.');
            redirect('/invoices');
        }

        $db->beginTransaction();
        try {
            $invoiceQuery = $db->prepare(
                "SELECT id, status, due_date, subtotal, discount_amount, tax_amount, penalty_amount
                 FROM invoices WHERE id = :id AND tenant_id = :tenant_id FOR UPDATE"
            );
            $invoiceQuery->execute(['id' => $invoiceId, 'tenant_id' => $tenantId]);
            $invoice = $invoiceQuery->fetch();
            if (!$invoice || $invoice['status'] !== 'unpaid') {
                throw new DomainException('Denda hanya dapat ditetapkan pada invoice yang belum lunas.');
            }
            if ($invoice['due_date'] >= date('Y-m-d')) {
                throw new DomainException('Invoice belum melewati tanggal jatuh tempo.');
            }

            $total = BillingService::totalWithPenalty(
                (float) $invoice['subtotal'],
                (float) $invoice['discount_amount'],
                (float) $invoice['tax_amount'],
                (float) $penaltyAmount
            );
            $update = $db->prepare(
                'UPDATE invoices SET penalty_amount = :penalty_amount, amount = :amount
                 WHERE id = :id AND tenant_id = :tenant_id'
            );
            $update->execute([
                'penalty_amount' => $penaltyAmount,
                'amount' => $total,
                'id' => $invoiceId,
                'tenant_id' => $tenantId,
            ]);
            $invalidatedMatches = PaymentReconciliationService::invalidateInvoiceMatches(
                $db,
                $tenantId,
                (int) $invoiceId,
                'amount_mismatch'
            );
            audit_event($db, 'invoice.penalty_updated', 'invoice', (int) $invoiceId, [
                'previous_penalty' => $invoice['penalty_amount'],
                'penalty_amount' => $penaltyAmount,
                'amount' => $total,
                'invalidated_matches' => $invalidatedMatches,
            ]);
            $db->commit();
            flash('success', 'Denda keterlambatan dan total invoice berhasil diperbarui.');
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            if ($exception instanceof DomainException || $exception instanceof InvalidArgumentException) {
                flash('error', $exception->getMessage());
            } else {
                throw $exception;
            }
        }
        redirect('/invoices/view?id=' . $invoiceId);
    }

    if ($action === 'generate') {
        $month = input('billing_month');
        $dueDate = input('due_date');
        $taxRate = filter_var(input('tax_rate', '0'), FILTER_VALIDATE_FLOAT);
        $periodStart = BillingService::periodStart($month);
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $dueDate);
        if ($periodStart === null || $taxRate === false || $taxRate < 0 || $taxRate > 100
            || !$date || $date->format('Y-m-d') !== $dueDate || $dueDate < $periodStart) {
            flash('error', 'Periode, pajak, atau jatuh tempo generator tidak valid.');
            redirect('/invoices');
        }

        $db->beginTransaction();
        try {
            $result = BillingService::generateMonthly($db, $tenantId, $month, $dueDate, (float) $taxRate);
            audit_event($db, 'invoice.monthly_generated', 'invoice_batch', null, [
                'month' => $month,
                'tax_rate' => $taxRate,
                'created' => $result['created'],
                'existing' => $result['existing'],
                'without_plan' => $result['without_plan'],
            ]);
            $db->commit();
            flash(
                'success',
                sprintf(
                    'Generator selesai: %d dibuat, %d sudah ada, %d tanpa paket aktif.',
                    $result['created'],
                    $result['existing'],
                    $result['without_plan']
                )
            );
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $exception;
        }
        redirect('/invoices');
    }

    $customerId = filter_var(input('customer_id'), FILTER_VALIDATE_INT);
    $baseAmount = filter_var(input('base_amount'), FILTER_VALIDATE_FLOAT);
    $discountAmount = filter_var(input('discount_amount', '0'), FILTER_VALIDATE_FLOAT);
    $taxRate = filter_var(input('tax_rate', '0'), FILTER_VALIDATE_FLOAT);
    $prorationInput = input('proration_days');
    $prorationDays = $prorationInput === '' ? null : filter_var($prorationInput, FILTER_VALIDATE_INT);
    $month = input('billing_month');
    $period = BillingService::monthLabel($month);
    $periodStart = BillingService::periodStart($month);
    $totalDays = BillingService::daysInMonth($month);
    $dueDate = input('due_date');
    $date = DateTimeImmutable::createFromFormat('!Y-m-d', $dueDate);
    if (!$customerId || $baseAmount === false || $discountAmount === false || $taxRate === false
        || $prorationDays === false || $period === null || $periodStart === null || $totalDays === null
        || !$date || $date->format('Y-m-d') !== $dueDate || $dueDate < $periodStart) {
        flash('error', 'Data tagihan belum valid.');
        redirect('/invoices');
    }
    try {
        $totals = BillingService::calculateTotals(
            (float) $baseAmount,
            (float) $taxRate,
            (float) $discountAmount,
            $prorationDays,
            $totalDays
        );
    } catch (InvalidArgumentException $exception) {
        flash('error', $exception->getMessage());
        redirect('/invoices');
    }
    $customer = $db->prepare('SELECT id FROM customers WHERE id = :id AND tenant_id = :tenant_id AND status != \'terminated\'');
    $customer->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
    if (!$customer->fetchColumn()) {
        flash('error', 'Pelanggan tidak ditemukan pada ISP ini.');
        redirect('/invoices');
    }
    $number = 'INV-' . date('Ymd') . '-' . strtoupper(bin2hex(random_bytes(3)));
    try {
        $insert = $db->prepare(
            "INSERT INTO invoices
                (tenant_id, customer_id, invoice_number, period_label, billing_period,
                 base_amount, subtotal, discount_amount, tax_rate, tax_amount, penalty_amount,
                 proration_days, proration_total_days, amount, due_date, source)
             VALUES
                (:tenant_id, :customer_id, :invoice_number, :period_label, :billing_period,
                 :base_amount, :subtotal, :discount_amount, :tax_rate, :tax_amount, :penalty_amount,
                 :proration_days, :proration_total_days, :amount, :due_date, 'manual')"
        );
        $insert->execute([
            'tenant_id' => $tenantId,
            'customer_id' => $customerId,
            'invoice_number' => $number,
            'period_label' => $period,
            'billing_period' => $periodStart,
            'base_amount' => $totals['base_amount'],
            'subtotal' => $totals['subtotal'],
            'discount_amount' => $totals['discount_amount'],
            'tax_rate' => $totals['tax_rate'],
            'tax_amount' => $totals['tax_amount'],
            'penalty_amount' => $totals['penalty_amount'],
            'proration_days' => $totals['proration_days'],
            'proration_total_days' => $totals['proration_total_days'],
            'amount' => $totals['amount'],
            'due_date' => $dueDate,
        ]);
        audit_event($db, 'invoice.created', 'invoice', (int) $db->lastInsertId(), [
            'number' => $number,
            'base_amount' => $totals['base_amount'],
            'subtotal' => $totals['subtotal'],
            'discount_amount' => $totals['discount_amount'],
            'tax_rate' => $totals['tax_rate'],
            'proration_days' => $totals['proration_days'],
            'amount' => $totals['amount'],
        ]);
        flash('success', 'Tagihan berhasil diterbitkan.');
    } catch (PDOException $exception) {
        if ($exception->getCode() === '23000') {
            flash('error', 'Tagihan pelanggan untuk periode tersebut sudah tersedia.');
        } else {
            throw $exception;
        }
    }
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

if ($path === '/reports/export' && $method === 'GET') {
    Auth::requireReportAccess();
    $type = query_input('type');
    if (!in_array($type, ['invoices', 'payments'], true)) {
        flash('error', 'Jenis export laporan tidak valid.');
        redirect('/reports');
    }
    try {
        $range = ReportService::normalizeRange(
            query_input('date_from', date('Y-m-01')),
            query_input('date_to', date('Y-m-d'))
        );
    } catch (InvalidArgumentException $exception) {
        flash('error', $exception->getMessage());
        redirect('/reports');
    }

    $tenantSlug = preg_replace('/[^A-Za-z0-9_-]/', '-', (string) (Auth::user()['tenant_slug'] ?? 'isp')) ?: 'isp';
    $reportName = $type === 'invoices' ? 'tagihan' : 'kas';
    $fileName = sprintf(
        '%s-%s-%s-%s.csv',
        $reportName,
        strtolower($tenantSlug),
        $range['date_from'],
        $range['date_to']
    );

    if ($type === 'invoices') {
        $exportQuery = $db->prepare(
            "SELECT i.invoice_number, c.customer_code, c.name AS customer_name,
                    i.period_label, i.base_amount, i.subtotal, i.discount_amount,
                    i.tax_rate, i.tax_amount, i.penalty_amount, i.amount,
                    i.due_date, i.status, i.created_at
             FROM invoices i
             INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
             WHERE i.tenant_id = :tenant_id AND i.status IN ('unpaid', 'paid')
               AND i.created_at >= :date_from AND i.created_at < :date_to
             ORDER BY i.created_at ASC, i.id ASC"
        );
        $headers = [
            'invoice_number', 'customer_code', 'customer_name', 'period', 'base_amount',
            'subtotal', 'discount_amount', 'tax_rate', 'tax_amount', 'penalty_amount',
            'total_amount', 'due_date', 'status', 'created_at',
        ];
    } else {
        $exportQuery = $db->prepare(
            'SELECT p.paid_at, i.invoice_number, c.customer_code, c.name AS customer_name,
                    p.amount, p.method, p.reference_number, u.name AS recorded_by
             FROM payments p
             INNER JOIN invoices i ON i.id = p.invoice_id AND i.tenant_id = p.tenant_id
             INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = p.tenant_id
             INNER JOIN users u ON u.id = p.recorded_by
             WHERE p.tenant_id = :tenant_id AND p.paid_at >= :date_from AND p.paid_at < :date_to
             ORDER BY p.paid_at ASC, p.id ASC'
        );
        $headers = [
            'paid_at', 'invoice_number', 'customer_code', 'customer_name',
            'amount', 'method', 'reference_number', 'recorded_by',
        ];
    }
    $exportQuery->execute([
        'tenant_id' => $tenantId,
        'date_from' => $range['start_at'],
        'date_to' => $range['end_before'],
    ]);

    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $fileName . '"');
    header('Cache-Control: no-store');
    $output = fopen('php://output', 'wb');
    if ($output === false) {
        throw new RuntimeException('File export CSV tidak dapat dibuat.');
    }
    fwrite($output, "\xEF\xBB\xBF");
    CsvService::writeRow($output, $headers);
    while ($row = $exportQuery->fetch()) {
        CsvService::writeRow($output, array_values($row));
    }
    fclose($output);
    exit;
}

if ($path === '/reports' && $method === 'GET') {
    Auth::requireReportAccess();
    $dateFrom = query_input('date_from', date('Y-m-01'));
    $dateTo = query_input('date_to', date('Y-m-d'));
    try {
        $range = ReportService::normalizeRange($dateFrom, $dateTo);
    } catch (InvalidArgumentException $exception) {
        flash('error', $exception->getMessage());
        redirect('/reports');
    }

    $today = date('Y-m-d');
    $agingBoundaries = ReportService::agingBoundaries($today);

    $issuedQuery = $db->prepare(
        "SELECT COUNT(*) AS invoice_count,
                COALESCE(SUM(base_amount), 0) AS base_total,
                COALESCE(SUM(discount_amount), 0) AS discount_total,
                COALESCE(SUM(tax_amount), 0) AS tax_total,
                COALESCE(SUM(penalty_amount), 0) AS penalty_total,
                COALESCE(SUM(amount), 0) AS billed_total
         FROM invoices
         WHERE tenant_id = :tenant_id AND status IN ('unpaid', 'paid')
           AND created_at >= :date_from AND created_at < :date_to"
    );
    $issuedQuery->execute([
        'tenant_id' => $tenantId,
        'date_from' => $range['start_at'],
        'date_to' => $range['end_before'],
    ]);
    $issued = $issuedQuery->fetch() ?: [];

    $cashSummaryQuery = $db->prepare(
        'SELECT COUNT(*) AS payment_count, COALESCE(SUM(amount), 0) AS cash_total
         FROM payments
         WHERE tenant_id = :tenant_id AND paid_at >= :date_from AND paid_at < :date_to'
    );
    $cashSummaryQuery->execute([
        'tenant_id' => $tenantId,
        'date_from' => $range['start_at'],
        'date_to' => $range['end_before'],
    ]);
    $cashSummary = $cashSummaryQuery->fetch() ?: [];

    $outstandingQuery = $db->prepare(
        "SELECT COUNT(*) AS invoice_count,
                COALESCE(SUM(amount), 0) AS outstanding_total,
                COUNT(CASE WHEN due_date < :overdue_count_today THEN 1 END) AS overdue_count,
                COALESCE(SUM(CASE WHEN due_date < :overdue_amount_today THEN amount ELSE 0 END), 0) AS overdue_total
         FROM invoices WHERE tenant_id = :tenant_id AND status = 'unpaid'"
    );
    $outstandingQuery->execute([
        'overdue_count_today' => $today,
        'overdue_amount_today' => $today,
        'tenant_id' => $tenantId,
    ]);
    $outstanding = $outstandingQuery->fetch() ?: [];

    $agingQuery = $db->prepare(
        "SELECT
            COALESCE(SUM(CASE WHEN due_date >= :current_today THEN amount ELSE 0 END), 0) AS current_total,
            COALESCE(SUM(CASE WHEN due_date < :late_today AND due_date >= :late_day_30 THEN amount ELSE 0 END), 0) AS day_1_30_total,
            COALESCE(SUM(CASE WHEN due_date < :day_31_before AND due_date >= :late_day_60 THEN amount ELSE 0 END), 0) AS day_31_60_total,
            COALESCE(SUM(CASE WHEN due_date < :day_61_before AND due_date >= :late_day_90 THEN amount ELSE 0 END), 0) AS day_61_90_total,
            COALESCE(SUM(CASE WHEN due_date < :day_90_before THEN amount ELSE 0 END), 0) AS over_90_total
         FROM invoices WHERE tenant_id = :tenant_id AND status = 'unpaid'"
    );
    $agingQuery->execute([
        'current_today' => $agingBoundaries['today'],
        'late_today' => $agingBoundaries['today'],
        'late_day_30' => $agingBoundaries['day_30'],
        'day_31_before' => $agingBoundaries['day_30'],
        'late_day_60' => $agingBoundaries['day_60'],
        'day_61_before' => $agingBoundaries['day_60'],
        'late_day_90' => $agingBoundaries['day_90'],
        'day_90_before' => $agingBoundaries['day_90'],
        'tenant_id' => $tenantId,
    ]);
    $aging = $agingQuery->fetch() ?: [];
    $agingRows = [
        ['label' => 'Belum jatuh tempo', 'total' => $aging['current_total'] ?? 0],
        ['label' => 'Terlambat 1–30 hari', 'total' => $aging['day_1_30_total'] ?? 0],
        ['label' => 'Terlambat 31–60 hari', 'total' => $aging['day_31_60_total'] ?? 0],
        ['label' => 'Terlambat 61–90 hari', 'total' => $aging['day_61_90_total'] ?? 0],
        ['label' => 'Terlambat lebih dari 90 hari', 'total' => $aging['over_90_total'] ?? 0],
    ];

    $cashMethodQuery = $db->prepare(
        'SELECT method, COUNT(*) AS payment_count, COALESCE(SUM(amount), 0) AS cash_total
         FROM payments
         WHERE tenant_id = :tenant_id AND paid_at >= :date_from AND paid_at < :date_to
         GROUP BY method ORDER BY cash_total DESC, method ASC'
    );
    $cashMethodQuery->execute([
        'tenant_id' => $tenantId,
        'date_from' => $range['start_at'],
        'date_to' => $range['end_before'],
    ]);
    $cashMethods = $cashMethodQuery->fetchAll();

    $dailyCashQuery = $db->prepare(
        'SELECT DATE(paid_at) AS report_date, COUNT(*) AS payment_count,
                COALESCE(SUM(amount), 0) AS cash_total
         FROM payments
         WHERE tenant_id = :tenant_id AND paid_at >= :date_from AND paid_at < :date_to
         GROUP BY DATE(paid_at) ORDER BY report_date DESC'
    );
    $dailyCashQuery->execute([
        'tenant_id' => $tenantId,
        'date_from' => $range['start_at'],
        'date_to' => $range['end_before'],
    ]);
    $dailyCash = $dailyCashQuery->fetchAll();

    $receivableQuery = $db->prepare(
        "SELECT i.id, i.invoice_number, i.due_date, i.amount,
                c.customer_code, c.name AS customer_name
         FROM invoices i
         INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
         WHERE i.tenant_id = :tenant_id AND i.status = 'unpaid'
         ORDER BY CASE WHEN i.due_date < :today THEN 0 ELSE 1 END, i.due_date ASC, i.id DESC
         LIMIT 20"
    );
    $receivableQuery->execute(['tenant_id' => $tenantId, 'today' => $today]);
    $receivables = $receivableQuery->fetchAll();

    $exportQueryString = http_build_query([
        'date_from' => $range['date_from'],
        'date_to' => $range['date_to'],
    ]);
    View::header('Laporan keuangan');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Kontrol keuangan</p><h1>Laporan piutang dan kas</h1></div>
        <div class="action-group">
            <span class="secure-badge"><?= e($range['date_from']) ?> — <?= e($range['date_to']) ?></span>
            <a class="button button-secondary" href="/reports/export?type=invoices&amp;<?= e($exportQueryString) ?>">Export tagihan CSV</a>
            <a class="button button-secondary" href="/reports/export?type=payments&amp;<?= e($exportQueryString) ?>">Export kas CSV</a>
        </div>
    </div>
    <section class="panel">
        <form method="get" class="report-filter">
            <label>Tanggal awal<input type="date" name="date_from" value="<?= e($range['date_from']) ?>" required></label>
            <label>Tanggal akhir<input type="date" name="date_to" value="<?= e($range['date_to']) ?>" required></label>
            <button class="button button-primary" type="submit">Tampilkan laporan</button>
            <a class="button button-secondary" href="/reports">Bulan berjalan</a>
        </form>
        <p class="muted report-definition">Pendapatan tagihan dan kas masuk mengikuti periode di atas. Piutang merupakan snapshot seluruh invoice yang masih belum lunas saat laporan dibuka.</p>
    </section>
    <section class="stat-grid">
        <article class="stat-card"><span>Pendapatan ditagihkan</span><strong><?= e(rupiah($issued['billed_total'] ?? 0)) ?></strong><small><?= e($issued['invoice_count'] ?? 0) ?> invoice tidak dibatalkan</small></article>
        <article class="stat-card stat-card-accent"><span>Kas masuk</span><strong><?= e(rupiah($cashSummary['cash_total'] ?? 0)) ?></strong><small><?= e($cashSummary['payment_count'] ?? 0) ?> pembayaran pada periode</small></article>
        <article class="stat-card"><span>Piutang aktif</span><strong><?= e(rupiah($outstanding['outstanding_total'] ?? 0)) ?></strong><small><?= e($outstanding['invoice_count'] ?? 0) ?> invoice belum lunas</small></article>
        <article class="stat-card"><span>Piutang overdue</span><strong><?= e(rupiah($outstanding['overdue_total'] ?? 0)) ?></strong><small><?= e($outstanding['overdue_count'] ?? 0) ?> melewati jatuh tempo</small></article>
    </section>
    <section class="report-grid">
        <article class="panel">
            <div class="section-heading"><div><h2>Rincian tagihan diterbitkan</h2><p class="muted">Komponen invoice dalam periode terpilih.</p></div></div>
            <dl class="detail-list report-totals">
                <div><dt>Harga dasar</dt><dd><?= e(rupiah($issued['base_total'] ?? 0)) ?></dd></div>
                <div><dt>Diskon</dt><dd>− <?= e(rupiah($issued['discount_total'] ?? 0)) ?></dd></div>
                <div><dt>Pajak</dt><dd><?= e(rupiah($issued['tax_total'] ?? 0)) ?></dd></div>
                <div><dt>Denda</dt><dd><?= e(rupiah($issued['penalty_total'] ?? 0)) ?></dd></div>
                <div class="report-total-row"><dt>Total ditagihkan</dt><dd><?= e(rupiah($issued['billed_total'] ?? 0)) ?></dd></div>
            </dl>
        </article>
        <article class="panel">
            <div class="section-heading"><div><h2>Aging piutang</h2><p class="muted">Umur seluruh invoice yang masih belum lunas.</p></div></div>
            <div class="table-wrap"><table><thead><tr><th>Kelompok umur</th><th>Nominal</th></tr></thead><tbody>
                <?php foreach ($agingRows as $row): ?><tr><td><?= e($row['label']) ?></td><td><strong><?= e(rupiah($row['total'])) ?></strong></td></tr><?php endforeach; ?>
            </tbody></table></div>
        </article>
    </section>
    <section class="report-grid">
        <article class="panel">
            <div class="section-heading"><div><h2>Kas berdasarkan metode</h2><p class="muted">Ringkasan cara pembayaran pada periode.</p></div></div>
            <div class="table-wrap"><table><thead><tr><th>Metode</th><th>Transaksi</th><th>Kas masuk</th></tr></thead><tbody>
                <?php if ($cashMethods === []): ?><tr><td colspan="3" class="muted">Belum ada pembayaran pada periode ini.</td></tr><?php endif; ?>
                <?php foreach ($cashMethods as $method): ?><tr><td><span class="role-badge"><?= e($method['method']) ?></span></td><td><?= e($method['payment_count']) ?></td><td><strong><?= e(rupiah($method['cash_total'])) ?></strong></td></tr><?php endforeach; ?>
            </tbody></table></div>
        </article>
        <article class="panel">
            <div class="section-heading"><div><h2>Kas harian</h2><p class="muted">Penerimaan per tanggal dalam zona waktu ISP.</p></div></div>
            <div class="table-wrap report-table-scroll"><table><thead><tr><th>Tanggal</th><th>Transaksi</th><th>Kas masuk</th></tr></thead><tbody>
                <?php if ($dailyCash === []): ?><tr><td colspan="3" class="muted">Belum ada penerimaan kas pada periode ini.</td></tr><?php endif; ?>
                <?php foreach ($dailyCash as $day): ?><tr><td><?= e($day['report_date']) ?></td><td><?= e($day['payment_count']) ?></td><td><strong><?= e(rupiah($day['cash_total'])) ?></strong></td></tr><?php endforeach; ?>
            </tbody></table></div>
        </article>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Prioritas penagihan</h2><p class="muted">Maksimal 20 invoice belum lunas, diurutkan dari jatuh tempo paling lama.</p></div><a class="button button-secondary" href="/invoices?status=overdue">Lihat semua overdue</a></div>
        <div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Pelanggan</th><th>Jatuh tempo</th><th>Umur</th><th>Piutang</th></tr></thead><tbody>
            <?php if ($receivables === []): ?><tr><td colspan="5" class="muted">Tidak ada invoice yang perlu ditagih.</td></tr><?php endif; ?>
            <?php foreach ($receivables as $receivable):
                $dueDate = new DateTimeImmutable($receivable['due_date']);
                $todayDate = new DateTimeImmutable($today);
                $daysOverdue = $dueDate < $todayDate ? (int) $dueDate->diff($todayDate)->days : 0;
                ?>
                <tr>
                    <td><a class="table-link" href="/invoices/view?id=<?= e($receivable['id']) ?>"><strong><?= e($receivable['invoice_number']) ?></strong></a></td>
                    <td><?= e($receivable['customer_code']) ?><small><?= e($receivable['customer_name']) ?></small></td>
                    <td><?= e($receivable['due_date']) ?></td>
                    <td><?= $daysOverdue > 0 ? e($daysOverdue . ' hari terlambat') : '<span class="status">Belum jatuh tempo</span>' ?></td>
                    <td><strong><?= e(rupiah($receivable['amount'])) ?></strong></td>
                </tr>
            <?php endforeach; ?>
        </tbody></table></div>
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

if ($path === '/customers/view') {
    $customerId = filter_var(query_input('id'), FILTER_VALIDATE_INT);
    if (!$customerId) {
        flash('error', 'Pelanggan tidak valid.');
        redirect('/customers');
    }

    $customerQuery = $db->prepare(
        'SELECT c.id, c.customer_code, c.name, c.phone, c.email, c.address, c.status,
                c.created_at, c.updated_at, p.id AS plan_id, p.code AS plan_code,
                p.name AS plan_name, p.speed_label, p.price AS plan_price, p.status AS plan_status
         FROM customers c
         LEFT JOIN plans p ON p.id = c.plan_id AND p.tenant_id = c.tenant_id
         WHERE c.id = :id AND c.tenant_id = :tenant_id LIMIT 1'
    );
    $customerQuery->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
    $customer = $customerQuery->fetch();
    if (!$customer) {
        flash('error', 'Pelanggan tidak ditemukan pada ISP ini.');
        redirect('/customers');
    }

    $summaryQuery = $db->prepare(
        "SELECT COUNT(*) AS invoice_count,
                COALESCE(SUM(CASE WHEN status = 'unpaid' THEN amount ELSE 0 END), 0) AS outstanding,
                COALESCE(SUM(CASE WHEN status = 'paid' THEN amount ELSE 0 END), 0) AS paid_total,
                MAX(created_at) AS last_invoice_at
         FROM invoices WHERE customer_id = :customer_id AND tenant_id = :tenant_id"
    );
    $summaryQuery->execute(['customer_id' => $customerId, 'tenant_id' => $tenantId]);
    $summary = $summaryQuery->fetch() ?: [];

    $invoiceQuery = $db->prepare(
        'SELECT id, invoice_number, period_label, amount, due_date, source, status, created_at
         FROM invoices WHERE customer_id = :customer_id AND tenant_id = :tenant_id
         ORDER BY id DESC LIMIT 20'
    );
    $invoiceQuery->execute(['customer_id' => $customerId, 'tenant_id' => $tenantId]);
    $customerInvoices = $invoiceQuery->fetchAll();

    $historyQuery = $db->prepare(
        "SELECT a.action, a.metadata_json, a.created_at, u.name AS actor_name
         FROM audit_logs a INNER JOIN users u ON u.id = a.user_id
         WHERE a.tenant_id = :tenant_id AND a.entity_type = 'customer' AND a.entity_id = :customer_id
         ORDER BY a.id DESC LIMIT 20"
    );
    $historyQuery->execute(['tenant_id' => $tenantId, 'customer_id' => $customerId]);
    $customerHistory = $historyQuery->fetchAll();

    View::header('Detail Pelanggan');
    ?>
    <div class="page-heading">
        <div>
            <p class="eyebrow">Detail pelanggan</p>
            <h1><?= e($customer['customer_code'] . ' · ' . $customer['name']) ?></h1>
            <span class="status status-<?= e($customer['status']) ?>"><?= e($customer['status']) ?></span>
        </div>
        <div class="action-group">
            <?php if (Auth::canManageBilling()): ?>
                <a class="button button-secondary" href="/customers/edit?id=<?= e($customer['id']) ?>">Edit</a>
                <?php if ($customer['status'] !== 'terminated'): ?>
                    <a class="button button-danger" href="/customers/archive?id=<?= e($customer['id']) ?>">Arsipkan</a>
                <?php endif; ?>
            <?php endif; ?>
            <a class="button button-link" href="/customers">Kembali</a>
        </div>
    </div>
    <section class="stat-grid">
        <article class="stat-card"><span>Total invoice</span><strong><?= e($summary['invoice_count'] ?? 0) ?></strong><small>Seluruh periode</small></article>
        <article class="stat-card"><span>Piutang</span><strong><?= e(rupiah($summary['outstanding'] ?? 0)) ?></strong><small>Invoice belum lunas</small></article>
        <article class="stat-card"><span>Sudah dibayar</span><strong><?= e(rupiah($summary['paid_total'] ?? 0)) ?></strong><small>Akumulasi pembayaran</small></article>
        <article class="stat-card"><span>Invoice terakhir</span><strong class="stat-date"><?= e($summary['last_invoice_at'] ?: '—') ?></strong><small>Waktu penerbitan</small></article>
    </section>
    <section class="account-grid detail-grid">
        <article class="panel">
            <h2>Kontak dan alamat</h2>
            <dl class="detail-list">
                <div><dt>WhatsApp</dt><dd><?= e($customer['phone'] ?: '—') ?></dd></div>
                <div><dt>Email</dt><dd><?= e($customer['email'] ?: '—') ?></dd></div>
                <div><dt>Alamat</dt><dd><?= nl2br(e($customer['address'] ?: '—')) ?></dd></div>
            </dl>
        </article>
        <article class="panel">
            <h2>Layanan saat ini</h2>
            <dl class="detail-list">
                <div><dt>Paket</dt><dd><?= e($customer['plan_name'] ?: 'Belum ditentukan') ?></dd></div>
                <div><dt>Kecepatan</dt><dd><?= e($customer['speed_label'] ?: '—') ?></dd></div>
                <div><dt>Harga bulanan</dt><dd><?= e($customer['plan_price'] !== null ? rupiah($customer['plan_price']) : '—') ?></dd></div>
                <div><dt>Dibuat</dt><dd><?= e($customer['created_at']) ?></dd></div>
                <div><dt>Terakhir diperbarui</dt><dd><?= e($customer['updated_at']) ?></dd></div>
            </dl>
        </article>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Histori tagihan</h2><p class="muted">Maksimal 20 invoice terbaru pelanggan ini.</p></div></div>
        <div class="table-wrap">
            <table><thead><tr><th>Invoice</th><th>Periode</th><th>Jatuh tempo</th><th>Nominal</th><th>Status</th></tr></thead><tbody>
                <?php if ($customerInvoices === []): ?><tr><td colspan="5" class="muted">Belum ada invoice.</td></tr><?php endif; ?>
                <?php foreach ($customerInvoices as $invoice): $overdue = $invoice['status'] === 'unpaid' && $invoice['due_date'] < date('Y-m-d'); ?>
                    <tr>
                        <td><a class="table-link" href="/invoices/view?id=<?= e($invoice['id']) ?>"><strong><?= e($invoice['invoice_number']) ?></strong></a><small><?= e($invoice['source']) ?></small></td>
                        <td><?= e($invoice['period_label']) ?></td><td><?= e($invoice['due_date']) ?></td>
                        <td><?= e(rupiah($invoice['amount'])) ?></td>
                        <td><span class="status status-<?= $overdue ? 'overdue' : e($invoice['status']) ?>"><?= $overdue ? 'overdue' : e($invoice['status']) ?></span></td>
                    </tr>
                <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Histori perubahan</h2><p class="muted">Aktivitas penting yang tercatat pada audit log.</p></div></div>
        <div class="table-wrap">
            <table><thead><tr><th>Waktu</th><th>Aktivitas</th><th>Oleh</th></tr></thead><tbody>
                <?php if ($customerHistory === []): ?><tr><td colspan="3" class="muted">Belum ada histori perubahan.</td></tr><?php endif; ?>
                <?php foreach ($customerHistory as $history): ?>
                    <tr><td><?= e($history['created_at']) ?></td><td><?= e($history['action']) ?></td><td><?= e($history['actor_name']) ?></td></tr>
                <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/customers/archive') {
    Auth::requireBillingAccess();
    $customerId = filter_var(query_input('id'), FILTER_VALIDATE_INT);
    if (!$customerId) {
        flash('error', 'Pelanggan tidak valid.');
        redirect('/customers');
    }

    $customerQuery = $db->prepare(
        'SELECT id, customer_code, name, status FROM customers
         WHERE id = :id AND tenant_id = :tenant_id LIMIT 1'
    );
    $customerQuery->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
    $customer = $customerQuery->fetch();
    if (!$customer) {
        flash('error', 'Pelanggan tidak ditemukan pada ISP ini.');
        redirect('/customers');
    }
    if ($customer['status'] === 'terminated') {
        flash('error', 'Pelanggan tersebut sudah diarsipkan.');
        redirect('/customers/view?id=' . $customerId);
    }

    $invoiceSummary = $db->prepare(
        "SELECT COUNT(*) AS invoice_count,
                COALESCE(SUM(CASE WHEN status = 'unpaid' THEN amount ELSE 0 END), 0) AS outstanding
         FROM invoices WHERE customer_id = :customer_id AND tenant_id = :tenant_id"
    );
    $invoiceSummary->execute(['customer_id' => $customerId, 'tenant_id' => $tenantId]);
    $summary = $invoiceSummary->fetch() ?: [];

    View::header('Arsipkan Pelanggan');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Konfirmasi aman</p><h1>Arsipkan pelanggan</h1></div>
        <a class="button button-secondary" href="/customers/view?id=<?= e($customer['id']) ?>">Batal</a>
    </div>
    <section class="panel danger-zone">
        <h2><?= e($customer['customer_code'] . ' · ' . $customer['name']) ?></h2>
        <p>Status pelanggan akan menjadi <strong>terminated</strong>. Pelanggan tidak akan menerima tagihan baru, tetapi seluruh invoice, pembayaran, dan audit log lama tetap tersimpan.</p>
        <dl class="detail-list archive-summary">
            <div><dt>Total invoice tersimpan</dt><dd><?= e($summary['invoice_count'] ?? 0) ?></dd></div>
            <div><dt>Piutang yang tetap tercatat</dt><dd><?= e(rupiah($summary['outstanding'] ?? 0)) ?></dd></div>
        </dl>
        <form method="post" action="/customers" class="confirm-form">
            <?= csrf_field() ?>
            <input type="hidden" name="_action" value="archive">
            <input type="hidden" name="customer_id" value="<?= e($customer['id']) ?>">
            <button class="button button-danger" type="submit">Ya, arsipkan pelanggan</button>
        </form>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/customers/edit') {
    Auth::requireBillingAccess();
    $customerId = filter_var(query_input('id'), FILTER_VALIDATE_INT);
    if (!$customerId) {
        flash('error', 'Pelanggan tidak valid.');
        redirect('/customers');
    }
    $customerQuery = $db->prepare(
        'SELECT id, plan_id, customer_code, name, phone, email, address, status
         FROM customers WHERE id = :id AND tenant_id = :tenant_id LIMIT 1'
    );
    $customerQuery->execute(['id' => $customerId, 'tenant_id' => $tenantId]);
    $customer = $customerQuery->fetch();
    if (!$customer) {
        flash('error', 'Pelanggan tidak ditemukan pada ISP ini.');
        redirect('/customers');
    }
    $plansQuery = $db->prepare(
        'SELECT id, name, speed_label, status FROM plans
         WHERE tenant_id = :tenant_id ORDER BY status, name'
    );
    $plansQuery->execute(['tenant_id' => $tenantId]);
    $plans = $plansQuery->fetchAll();
    View::header('Edit Pelanggan');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Master data</p><h1>Edit pelanggan</h1></div>
        <div class="action-group">
            <?php if ($customer['status'] !== 'terminated'): ?><a class="button button-danger" href="/customers/archive?id=<?= e($customer['id']) ?>">Arsipkan</a><?php endif; ?>
            <a class="button button-secondary" href="/customers/view?id=<?= e($customer['id']) ?>">Kembali</a>
        </div>
    </div>
    <section class="panel">
        <form method="post" action="/customers" class="form-grid">
            <?= csrf_field() ?>
            <input type="hidden" name="_action" value="update">
            <input type="hidden" name="customer_id" value="<?= e($customer['id']) ?>">
            <label>Kode pelanggan<input name="customer_code" maxlength="30" required value="<?= e($customer['customer_code']) ?>"></label>
            <label>Nama lengkap<input name="name" maxlength="120" required value="<?= e($customer['name']) ?>"></label>
            <label>Nomor WhatsApp<input name="phone" maxlength="30" value="<?= e($customer['phone']) ?>"></label>
            <label>Email<input type="email" name="email" maxlength="190" value="<?= e($customer['email'] ?? '') ?>"></label>
            <label>Paket
                <select name="plan_id">
                    <option value="">Belum ditentukan</option>
                    <?php foreach ($plans as $plan): ?>
                        <option value="<?= e($plan['id']) ?>"<?= (int) $customer['plan_id'] === (int) $plan['id'] ? ' selected' : '' ?>>
                            <?= e($plan['name'] . ' · ' . $plan['speed_label'] . ($plan['status'] === 'inactive' ? ' (nonaktif)' : '')) ?>
                        </option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label>Status
                <select name="status" required>
                    <?php foreach (['active' => 'Aktif', 'suspended' => 'Suspend', 'terminated' => 'Berhenti'] as $value => $label): ?>
                        <option value="<?= e($value) ?>"<?= $customer['status'] === $value ? ' selected' : '' ?>><?= e($label) ?></option>
                    <?php endforeach; ?>
                </select>
            </label>
            <label class="field-wide">Alamat<textarea name="address" rows="3"><?= e($customer['address'] ?? '') ?></textarea></label>
            <div class="field-wide"><button class="button button-primary" type="submit">Simpan perubahan</button></div>
        </form>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/plans/edit') {
    Auth::requireBillingAccess();
    $planId = filter_var(query_input('id'), FILTER_VALIDATE_INT);
    if (!$planId) {
        flash('error', 'Paket tidak valid.');
        redirect('/plans');
    }
    $planQuery = $db->prepare(
        'SELECT id, code, name, speed_label, price, status
         FROM plans WHERE id = :id AND tenant_id = :tenant_id LIMIT 1'
    );
    $planQuery->execute(['id' => $planId, 'tenant_id' => $tenantId]);
    $plan = $planQuery->fetch();
    if (!$plan) {
        flash('error', 'Paket tidak ditemukan pada ISP ini.');
        redirect('/plans');
    }
    View::header('Edit Paket');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Produk layanan</p><h1>Edit paket</h1></div>
        <div class="action-group">
            <?php if ($plan['status'] === 'active'): ?><a class="button button-danger" href="/plans/archive?id=<?= e($plan['id']) ?>">Arsipkan</a><?php endif; ?>
            <a class="button button-secondary" href="/plans">Kembali</a>
        </div>
    </div>
    <section class="panel">
        <form method="post" action="/plans" class="form-grid">
            <?= csrf_field() ?>
            <input type="hidden" name="_action" value="update">
            <input type="hidden" name="plan_id" value="<?= e($plan['id']) ?>">
            <label>Kode paket<input name="code" maxlength="30" required value="<?= e($plan['code']) ?>"></label>
            <label>Nama paket<input name="name" maxlength="120" required value="<?= e($plan['name']) ?>"></label>
            <label>Kecepatan<input name="speed_label" maxlength="80" required value="<?= e($plan['speed_label']) ?>"></label>
            <label>Harga bulanan<input type="number" name="price" min="0" step="1000" required value="<?= e($plan['price']) ?>"></label>
            <label>Status
                <select name="status" required>
                    <option value="active"<?= $plan['status'] === 'active' ? ' selected' : '' ?>>Aktif</option>
                    <option value="inactive"<?= $plan['status'] === 'inactive' ? ' selected' : '' ?>>Nonaktif</option>
                </select>
            </label>
            <div class="field-wide"><button class="button button-primary" type="submit">Simpan perubahan</button></div>
        </form>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/plans/archive') {
    Auth::requireBillingAccess();
    $planId = filter_var(query_input('id'), FILTER_VALIDATE_INT);
    if (!$planId) {
        flash('error', 'Paket tidak valid.');
        redirect('/plans');
    }

    $planQuery = $db->prepare(
        'SELECT id, code, name, speed_label, price, status FROM plans
         WHERE id = :id AND tenant_id = :tenant_id LIMIT 1'
    );
    $planQuery->execute(['id' => $planId, 'tenant_id' => $tenantId]);
    $plan = $planQuery->fetch();
    if (!$plan) {
        flash('error', 'Paket tidak ditemukan pada ISP ini.');
        redirect('/plans');
    }
    if ($plan['status'] === 'inactive') {
        flash('error', 'Paket tersebut sudah nonaktif atau diarsipkan.');
        redirect('/plans/edit?id=' . $planId);
    }

    $customerSummary = $db->prepare(
        "SELECT COUNT(*) AS customer_count,
                COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END), 0) AS active_count
         FROM customers WHERE plan_id = :plan_id AND tenant_id = :tenant_id"
    );
    $customerSummary->execute(['plan_id' => $planId, 'tenant_id' => $tenantId]);
    $summary = $customerSummary->fetch() ?: [];

    View::header('Arsipkan Paket');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Konfirmasi aman</p><h1>Arsipkan paket</h1></div>
        <a class="button button-secondary" href="/plans/edit?id=<?= e($plan['id']) ?>">Batal</a>
    </div>
    <section class="panel danger-zone">
        <h2><?= e($plan['code'] . ' · ' . $plan['name']) ?></h2>
        <p>Paket akan menjadi <strong>inactive</strong> dan tidak dipakai generator tagihan berikutnya. Relasi pelanggan serta histori invoice tetap tersimpan.</p>
        <dl class="detail-list archive-summary">
            <div><dt>Total pelanggan pada paket</dt><dd><?= e($summary['customer_count'] ?? 0) ?></dd></div>
            <div><dt>Pelanggan aktif terdampak</dt><dd><?= e($summary['active_count'] ?? 0) ?></dd></div>
            <div><dt>Harga terakhir</dt><dd><?= e(rupiah($plan['price'])) ?></dd></div>
        </dl>
        <form method="post" action="/plans" class="confirm-form">
            <?= csrf_field() ?>
            <input type="hidden" name="_action" value="archive">
            <input type="hidden" name="plan_id" value="<?= e($plan['id']) ?>">
            <button class="button button-danger" type="submit">Ya, arsipkan paket</button>
        </form>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/customers') {
    $plansQuery = $db->prepare("SELECT id, name, speed_label FROM plans WHERE tenant_id = :tenant_id AND status = 'active' ORDER BY name");
    $plansQuery->execute(['tenant_id' => $tenantId]);
    $plans = $plansQuery->fetchAll();

    $search = substr(query_input('q'), 0, 80);
    $statusFilter = query_input('status');
    if (!in_array($statusFilter, ['', 'active', 'suspended', 'terminated'], true)) {
        $statusFilter = '';
    }
    $where = ['c.tenant_id = :tenant_id'];
    $params = ['tenant_id' => $tenantId];
    if ($search !== '') {
        $where[] = "CONCAT_WS(' ', c.customer_code, c.name, c.phone, COALESCE(c.email, '')) LIKE :search";
        $params['search'] = '%' . $search . '%';
    }
    if ($statusFilter !== '') {
        $where[] = 'c.status = :status';
        $params['status'] = $statusFilter;
    }
    $whereSql = implode(' AND ', $where);
    $countQuery = $db->prepare('SELECT COUNT(*) FROM customers c WHERE ' . $whereSql);
    $countQuery->execute($params);
    $pagination = new Pagination((int) $countQuery->fetchColumn(), requested_page());
    $customersQuery = $db->prepare(
        'SELECT c.id, c.customer_code, c.name, c.phone, c.email, c.status,
                p.name AS plan_name, p.speed_label
         FROM customers c LEFT JOIN plans p ON p.id = c.plan_id AND p.tenant_id = c.tenant_id
         WHERE ' . $whereSql . '
         ORDER BY c.id DESC LIMIT :limit OFFSET :offset'
    );
    foreach ($params as $key => $value) {
        $customersQuery->bindValue(':' . $key, $value);
    }
    $customersQuery->bindValue(':limit', $pagination->perPage, PDO::PARAM_INT);
    $customersQuery->bindValue(':offset', $pagination->offset(), PDO::PARAM_INT);
    $customersQuery->execute();
    $customers = $customersQuery->fetchAll();
    View::header('Pelanggan');
    ?>
    <div class="page-heading">
        <div><p class="eyebrow">Master data</p><h1>Pelanggan</h1></div>
        <?php if (Auth::canManageBilling()): ?><a class="button button-secondary" href="/customers/import">Import CSV</a><?php endif; ?>
    </div>
    <?php if (Auth::canManageBilling()): ?>
    <section class="panel">
        <h2>Tambah pelanggan</h2>
        <form method="post" class="form-grid">
            <?= csrf_field() ?><input type="hidden" name="_action" value="create">
            <label>Kode pelanggan<input name="customer_code" maxlength="30" required placeholder="CUST-001"></label>
            <label>Nama lengkap<input name="name" maxlength="120" required></label>
            <label>Nomor WhatsApp<input name="phone" maxlength="30"></label>
            <label>Email<input type="email" name="email" maxlength="190"></label>
            <label>Paket<select name="plan_id"><option value="">Belum ditentukan</option><?php foreach ($plans as $plan): ?><option value="<?= e($plan['id']) ?>"><?= e($plan['name'] . ' · ' . $plan['speed_label']) ?></option><?php endforeach; ?></select></label>
            <label class="field-wide">Alamat<textarea name="address" rows="2"></textarea></label>
            <div class="field-wide"><button class="button button-primary" type="submit">Simpan pelanggan</button></div>
        </form>
    </section>
    <?php endif; ?>
    <section class="panel">
        <div class="section-heading"><div><h2>Daftar pelanggan</h2><p class="muted">Cari berdasarkan kode, nama, WhatsApp, atau email.</p></div></div>
        <form method="get" class="filter-form">
            <label>Pencarian<input name="q" maxlength="80" value="<?= e($search) ?>" placeholder="Kode atau nama pelanggan"></label>
            <label>Status<select name="status"><option value="">Semua status</option><option value="active"<?= $statusFilter === 'active' ? ' selected' : '' ?>>Aktif</option><option value="suspended"<?= $statusFilter === 'suspended' ? ' selected' : '' ?>>Suspend</option><option value="terminated"<?= $statusFilter === 'terminated' ? ' selected' : '' ?>>Berhenti</option></select></label>
            <button class="button button-primary" type="submit">Terapkan</button>
            <a class="button button-secondary" href="/customers">Reset</a>
        </form>
        <div class="table-wrap">
            <table><thead><tr><th>Kode</th><th>Nama</th><th>Paket</th><th>Kontak</th><th>Status</th><th>Aksi</th></tr></thead>
                <tbody>
                <?php if ($customers === []): ?><tr><td colspan="6" class="muted">Belum ada pelanggan yang sesuai.</td></tr><?php endif; ?>
                <?php foreach ($customers as $customer): ?>
                    <tr>
                        <td><a class="table-link" href="/customers/view?id=<?= e($customer['id']) ?>"><strong><?= e($customer['customer_code']) ?></strong></a></td>
                        <td><?= e($customer['name']) ?></td>
                        <td><?= e($customer['plan_name'] ?? '—') ?><small><?= e($customer['speed_label'] ?? '') ?></small></td>
                        <td><?= e($customer['phone'] ?: '—') ?><small><?= e($customer['email'] ?: '') ?></small></td>
                        <td><span class="status status-<?= e($customer['status']) ?>"><?= e($customer['status']) ?></span></td>
                        <td><div class="action-group"><a class="button button-link" href="/customers/view?id=<?= e($customer['id']) ?>">Detail</a><?php if (Auth::canManageBilling()): ?><a class="button button-link" href="/customers/edit?id=<?= e($customer['id']) ?>">Edit</a><?php endif; ?></div></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php View::pagination($pagination); ?>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/plans') {
    $search = substr(query_input('q'), 0, 80);
    $statusFilter = query_input('status');
    if (!in_array($statusFilter, ['', 'active', 'inactive'], true)) {
        $statusFilter = '';
    }
    $where = ['tenant_id = :tenant_id'];
    $params = ['tenant_id' => $tenantId];
    if ($search !== '') {
        $where[] = "CONCAT_WS(' ', code, name, speed_label) LIKE :search";
        $params['search'] = '%' . $search . '%';
    }
    if ($statusFilter !== '') {
        $where[] = 'status = :status';
        $params['status'] = $statusFilter;
    }
    $whereSql = implode(' AND ', $where);
    $countQuery = $db->prepare('SELECT COUNT(*) FROM plans WHERE ' . $whereSql);
    $countQuery->execute($params);
    $pagination = new Pagination((int) $countQuery->fetchColumn(), requested_page());
    $plansQuery = $db->prepare(
        'SELECT id, code, name, speed_label, price, status FROM plans
         WHERE ' . $whereSql . ' ORDER BY id DESC LIMIT :limit OFFSET :offset'
    );
    foreach ($params as $key => $value) {
        $plansQuery->bindValue(':' . $key, $value);
    }
    $plansQuery->bindValue(':limit', $pagination->perPage, PDO::PARAM_INT);
    $plansQuery->bindValue(':offset', $pagination->offset(), PDO::PARAM_INT);
    $plansQuery->execute();
    $plans = $plansQuery->fetchAll();
    View::header('Paket');
    ?>
    <div class="page-heading"><div><p class="eyebrow">Produk layanan</p><h1>Paket internet</h1></div></div>
    <?php if (Auth::canManageBilling()): ?>
        <section class="panel">
            <h2>Tambah paket</h2>
            <form method="post" class="form-grid">
                <?= csrf_field() ?><input type="hidden" name="_action" value="create">
                <label>Kode paket<input name="code" maxlength="30" required placeholder="HOME-20"></label>
                <label>Nama paket<input name="name" maxlength="120" required></label>
                <label>Kecepatan<input name="speed_label" maxlength="80" required placeholder="20 Mbps"></label>
                <label>Harga bulanan<input type="number" name="price" min="0" step="1000" required></label>
                <div class="field-wide"><button class="button button-primary" type="submit">Simpan paket</button></div>
            </form>
        </section>
    <?php endif; ?>
    <section class="panel">
        <div class="section-heading"><div><h2>Daftar paket</h2><p class="muted">Cari berdasarkan kode, nama, atau kecepatan.</p></div></div>
        <form method="get" class="filter-form">
            <label>Pencarian<input name="q" maxlength="80" value="<?= e($search) ?>" placeholder="Kode atau nama paket"></label>
            <label>Status<select name="status"><option value="">Semua status</option><option value="active"<?= $statusFilter === 'active' ? ' selected' : '' ?>>Aktif</option><option value="inactive"<?= $statusFilter === 'inactive' ? ' selected' : '' ?>>Nonaktif</option></select></label>
            <button class="button button-primary" type="submit">Terapkan</button>
            <a class="button button-secondary" href="/plans">Reset</a>
        </form>
        <div class="table-wrap">
            <table><thead><tr><th>Kode</th><th>Nama</th><th>Kecepatan</th><th>Harga</th><th>Status</th><th>Aksi</th></tr></thead>
                <tbody>
                <?php if ($plans === []): ?><tr><td colspan="6" class="muted">Belum ada paket yang sesuai.</td></tr><?php endif; ?>
                <?php foreach ($plans as $plan): ?>
                    <tr>
                        <td><strong><?= e($plan['code']) ?></strong></td><td><?= e($plan['name']) ?></td>
                        <td><?= e($plan['speed_label']) ?></td><td><?= e(rupiah($plan['price'])) ?></td>
                        <td><span class="status status-<?= e($plan['status']) ?>"><?= e($plan['status']) ?></span></td>
                        <td><?php if (Auth::canManageBilling()): ?><div class="action-group"><a class="button button-link" href="/plans/edit?id=<?= e($plan['id']) ?>">Edit</a><?php if ($plan['status'] === 'active'): ?><a class="button button-danger" href="/plans/archive?id=<?= e($plan['id']) ?>">Arsipkan</a><?php endif; ?></div><?php else: ?>—<?php endif; ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php View::pagination($pagination); ?>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/invoices/print') {
    $invoiceId = filter_var(query_input('id'), FILTER_VALIDATE_INT);
    if (!$invoiceId) {
        flash('error', 'Invoice tidak valid.');
        redirect('/invoices');
    }

    $printQuery = $db->prepare(
        'SELECT i.id, i.invoice_number, i.period_label, i.base_amount, i.subtotal,
                i.discount_amount, i.tax_rate, i.tax_amount, i.penalty_amount,
                i.proration_days, i.proration_total_days, i.amount, i.due_date,
                i.status, i.paid_at, i.created_at, c.customer_code, c.name AS customer_name,
                c.phone, c.email, c.address, t.name AS tenant_name
         FROM invoices i
         INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
         INNER JOIN tenants t ON t.id = i.tenant_id
         WHERE i.id = :id AND i.tenant_id = :tenant_id LIMIT 1'
    );
    $printQuery->execute(['id' => $invoiceId, 'tenant_id' => $tenantId]);
    $invoice = $printQuery->fetch();
    if (!$invoice) {
        flash('error', 'Invoice tidak ditemukan pada ISP ini.');
        redirect('/invoices');
    }
    ?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title><?= e($invoice['invoice_number']) ?> · <?= e($invoice['tenant_name']) ?></title>
    <link rel="stylesheet" href="/assets/app.css">
</head>
<body class="print-body">
<main class="invoice-print-shell">
    <div class="print-help no-print">
        <div><strong>Invoice siap dicetak</strong><small>Tekan Ctrl+P, lalu pilih “Save as PDF” atau printer.</small></div>
        <a class="button button-secondary" href="/invoices/view?id=<?= e($invoice['id']) ?>">Kembali ke detail</a>
    </div>
    <article class="invoice-document">
        <header class="invoice-header">
            <div><span class="invoice-brand-mark">RS</span><h1><?= e($invoice['tenant_name']) ?></h1><p>Billing layanan internet</p></div>
            <div class="invoice-number"><span>INVOICE</span><strong><?= e($invoice['invoice_number']) ?></strong><small>Diterbitkan <?= e(substr($invoice['created_at'], 0, 10)) ?></small></div>
        </header>
        <section class="invoice-meta-grid">
            <div><h2>Ditagihkan kepada</h2><strong><?= e($invoice['customer_code'] . ' · ' . $invoice['customer_name']) ?></strong><p><?= nl2br(e($invoice['address'] ?: 'Alamat belum tersedia')) ?></p><small><?= e($invoice['phone'] ?: '—') ?> · <?= e($invoice['email'] ?: '—') ?></small></div>
            <div><h2>Informasi tagihan</h2><dl><div><dt>Periode</dt><dd><?= e($invoice['period_label']) ?></dd></div><div><dt>Jatuh tempo</dt><dd><?= e($invoice['due_date']) ?></dd></div><div><dt>Status</dt><dd><?= e(strtoupper($invoice['status'])) ?></dd></div></dl></div>
        </section>
        <table class="invoice-breakdown">
            <thead><tr><th>Komponen</th><th>Keterangan</th><th>Jumlah</th></tr></thead>
            <tbody>
                <tr><td>Layanan internet</td><td><?= $invoice['proration_days'] !== null ? e('Prorata ' . $invoice['proration_days'] . '/' . $invoice['proration_total_days'] . ' hari dari ' . rupiah($invoice['base_amount'])) : 'Satu periode penuh' ?></td><td><?= e(rupiah($invoice['subtotal'])) ?></td></tr>
                <?php if ((float) $invoice['discount_amount'] > 0): ?><tr><td>Diskon</td><td>Potongan tagihan</td><td>− <?= e(rupiah($invoice['discount_amount'])) ?></td></tr><?php endif; ?>
                <?php if ((float) $invoice['tax_amount'] > 0): ?><tr><td>Pajak</td><td><?= e($invoice['tax_rate']) ?>%</td><td><?= e(rupiah($invoice['tax_amount'])) ?></td></tr><?php endif; ?>
                <?php if ((float) $invoice['penalty_amount'] > 0): ?><tr><td>Denda</td><td>Keterlambatan pembayaran</td><td><?= e(rupiah($invoice['penalty_amount'])) ?></td></tr><?php endif; ?>
            </tbody>
            <tfoot><tr><th colspan="2">TOTAL</th><th><?= e(rupiah($invoice['amount'])) ?></th></tr></tfoot>
        </table>
        <section class="invoice-note">
            <h2>Catatan</h2>
            <p>Simpan invoice ini sebagai bukti tagihan. Hubungi ISP apabila terdapat perbedaan data atau pembayaran belum tercatat.</p>
        </section>
        <footer class="invoice-footer"><span>RS Billing · Invoice multi-tenant</span><span>Dicetak <?= e(date('Y-m-d H:i')) ?></span></footer>
    </article>
</main>
</body>
</html>
    <?php
    exit;
}

if ($path === '/invoices/view') {
    $invoiceId = filter_var(query_input('id'), FILTER_VALIDATE_INT);
    if (!$invoiceId) {
        flash('error', 'Invoice tidak valid.');
        redirect('/invoices');
    }

    $invoiceQuery = $db->prepare(
        'SELECT i.id, i.invoice_number, i.period_label, i.billing_period, i.base_amount,
                i.subtotal, i.discount_amount, i.tax_rate, i.tax_amount, i.penalty_amount,
                i.proration_days, i.proration_total_days, i.amount, i.due_date,
                i.source, i.status, i.paid_at, i.created_at, i.updated_at,
                c.id AS customer_id, c.customer_code, c.name AS customer_name, c.phone,
                c.email, c.status AS customer_status, p.name AS plan_name, p.speed_label
         FROM invoices i
         INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
         LEFT JOIN plans p ON p.id = c.plan_id AND p.tenant_id = c.tenant_id
         WHERE i.id = :id AND i.tenant_id = :tenant_id LIMIT 1'
    );
    $invoiceQuery->execute(['id' => $invoiceId, 'tenant_id' => $tenantId]);
    $invoice = $invoiceQuery->fetch();
    if (!$invoice) {
        flash('error', 'Invoice tidak ditemukan pada ISP ini.');
        redirect('/invoices');
    }

    $paymentsQuery = $db->prepare(
        'SELECT p.id, p.amount, p.method, p.reference_number, p.paid_at, u.name AS recorded_by_name
         FROM payments p INNER JOIN users u ON u.id = p.recorded_by
         WHERE p.invoice_id = :invoice_id AND p.tenant_id = :tenant_id
         ORDER BY p.id DESC'
    );
    $paymentsQuery->execute(['invoice_id' => $invoiceId, 'tenant_id' => $tenantId]);
    $invoicePayments = $paymentsQuery->fetchAll();

    $notificationQuery = $db->prepare(
        'SELECT id, channel, recipient, template, status, attempts, max_attempts, created_at, sent_at
         FROM notification_outbox
         WHERE invoice_id = :invoice_id AND tenant_id = :tenant_id
         ORDER BY id DESC LIMIT 20'
    );
    $notificationQuery->execute(['invoice_id' => $invoiceId, 'tenant_id' => $tenantId]);
    $invoiceNotifications = $notificationQuery->fetchAll();

    $historyQuery = $db->prepare(
        "SELECT a.action, a.metadata_json, a.created_at, u.name AS actor_name
         FROM audit_logs a INNER JOIN users u ON u.id = a.user_id
         WHERE a.tenant_id = :tenant_id AND a.entity_type = 'invoice' AND a.entity_id = :invoice_id
         ORDER BY a.id DESC LIMIT 30"
    );
    $historyQuery->execute(['tenant_id' => $tenantId, 'invoice_id' => $invoiceId]);
    $invoiceHistory = $historyQuery->fetchAll();
    $overdue = $invoice['status'] === 'unpaid' && $invoice['due_date'] < date('Y-m-d');

    View::header('Detail Invoice');
    ?>
    <div class="page-heading">
        <div>
            <p class="eyebrow">Detail invoice</p>
            <h1><?= e($invoice['invoice_number']) ?></h1>
            <span class="status status-<?= $overdue ? 'overdue' : e($invoice['status']) ?>"><?= $overdue ? 'overdue' : e($invoice['status']) ?></span>
        </div>
        <div class="action-group">
            <a class="button button-secondary" href="/invoices/print?id=<?= e($invoice['id']) ?>">Cetak / Simpan PDF</a>
            <?php if ($invoice['status'] === 'unpaid' && Auth::canManageBilling()): ?>
                <form method="post" action="/invoices" class="inline-form">
                    <?= csrf_field() ?><input type="hidden" name="_action" value="pay"><input type="hidden" name="invoice_id" value="<?= e($invoice['id']) ?>">
                    <button class="button button-small" type="submit">Tandai lunas</button>
                </form>
                <form method="post" action="/invoices" class="inline-form">
                    <?= csrf_field() ?><input type="hidden" name="_action" value="cancel"><input type="hidden" name="invoice_id" value="<?= e($invoice['id']) ?>">
                    <button class="button button-danger" type="submit">Batalkan</button>
                </form>
            <?php endif; ?>
            <a class="button button-link" href="/invoices">Kembali</a>
        </div>
    </div>
    <section class="account-grid detail-grid">
        <article class="panel">
            <h2>Informasi tagihan</h2>
            <dl class="detail-list">
                <div><dt>Periode</dt><dd><?= e($invoice['period_label']) ?></dd></div>
                <div><dt>Harga dasar</dt><dd><?= e(rupiah($invoice['base_amount'])) ?></dd></div>
                <?php if ($invoice['proration_days'] !== null): ?><div><dt>Prorata</dt><dd><?= e($invoice['proration_days'] . ' dari ' . $invoice['proration_total_days'] . ' hari') ?></dd></div><?php endif; ?>
                <div><dt>Subtotal</dt><dd><?= e(rupiah($invoice['subtotal'])) ?></dd></div>
                <div><dt>Diskon</dt><dd>− <?= e(rupiah($invoice['discount_amount'])) ?></dd></div>
                <div><dt>Pajak</dt><dd><?= e($invoice['tax_rate']) ?>% · <?= e(rupiah($invoice['tax_amount'])) ?></dd></div>
                <div><dt>Denda</dt><dd><?= e(rupiah($invoice['penalty_amount'])) ?></dd></div>
                <div><dt>Total</dt><dd><strong><?= e(rupiah($invoice['amount'])) ?></strong></dd></div>
                <div><dt>Jatuh tempo</dt><dd><?= e($invoice['due_date']) ?></dd></div>
                <div><dt>Sumber</dt><dd><span class="role-badge"><?= e($invoice['source']) ?></span></dd></div>
                <div><dt>Dibuat</dt><dd><?= e($invoice['created_at']) ?></dd></div>
                <div><dt>Dibayar</dt><dd><?= e($invoice['paid_at'] ?: '—') ?></dd></div>
            </dl>
        </article>
        <article class="panel">
            <h2>Pelanggan</h2>
            <dl class="detail-list">
                <div><dt>Kode</dt><dd><a class="table-link" href="/customers/view?id=<?= e($invoice['customer_id']) ?>"><?= e($invoice['customer_code']) ?></a></dd></div>
                <div><dt>Nama</dt><dd><?= e($invoice['customer_name']) ?></dd></div>
                <div><dt>WhatsApp</dt><dd><?= e($invoice['phone'] ?: '—') ?></dd></div>
                <div><dt>Email</dt><dd><?= e($invoice['email'] ?: '—') ?></dd></div>
                <div><dt>Paket</dt><dd><?= e($invoice['plan_name'] ?: '—') ?><small><?= e($invoice['speed_label'] ?: '') ?></small></dd></div>
                <div><dt>Status pelanggan</dt><dd><span class="status status-<?= e($invoice['customer_status']) ?>"><?= e($invoice['customer_status']) ?></span></dd></div>
            </dl>
        </article>
    </section>
    <?php if ($invoice['status'] === 'unpaid' && Auth::canManageBilling()): ?>
        <section class="panel">
            <div class="section-heading"><div><h2>Antrekan pengingat</h2><p class="muted">Pesan disimpan secara idempotent pada outbox internal. Pengiriman provider belum diaktifkan.</p></div><a class="button button-secondary" href="/notifications">Lihat antrean</a></div>
            <?php if ($invoice['phone'] !== '' || $invoice['email']): ?>
                <form method="post" action="/notifications" class="form-grid compact-form">
                    <?= csrf_field() ?><input type="hidden" name="_action" value="enqueue"><input type="hidden" name="invoice_id" value="<?= e($invoice['id']) ?>">
                    <label>Kanal<select name="channel" required>
                        <?php if ($invoice['phone'] !== ''): ?><option value="whatsapp">WhatsApp · <?= e($invoice['phone']) ?></option><?php endif; ?>
                        <?php if ($invoice['email']): ?><option value="email">Email · <?= e($invoice['email']) ?></option><?php endif; ?>
                    </select></label>
                    <div class="form-action"><button class="button button-primary" type="submit">Masukkan antrean</button></div>
                </form>
            <?php else: ?>
                <p class="muted">Tambahkan nomor WhatsApp atau email pelanggan sebelum membuat pengingat.</p>
            <?php endif; ?>
        </section>
    <?php endif; ?>
    <?php if ($overdue && Auth::canManageBilling()): ?>
        <section class="panel notice-panel">
            <div class="section-heading"><div><h2>Denda keterlambatan</h2><p class="muted">Nilai yang dimasukkan menggantikan denda lama, sehingga aman jika formulir dikirim ulang.</p></div><span class="status status-overdue">overdue</span></div>
            <form method="post" action="/invoices" class="form-grid compact-form">
                <?= csrf_field() ?><input type="hidden" name="_action" value="penalty"><input type="hidden" name="invoice_id" value="<?= e($invoice['id']) ?>">
                <label>Nominal denda<input type="number" name="penalty_amount" min="0" step="1000" value="<?= e($invoice['penalty_amount']) ?>" required></label>
                <div class="form-action"><button class="button button-danger" type="submit">Perbarui denda</button></div>
            </form>
        </section>
    <?php endif; ?>
    <section class="panel">
        <div class="section-heading"><div><h2>Histori notifikasi</h2><p class="muted">Maksimal 20 antrean terbaru untuk invoice ini.</p></div></div>
        <div class="table-wrap">
            <table><thead><tr><th>Waktu</th><th>Kanal</th><th>Tujuan</th><th>Template</th><th>Status</th><th>Percobaan</th></tr></thead><tbody>
                <?php if ($invoiceNotifications === []): ?><tr><td colspan="6" class="muted">Belum ada notifikasi.</td></tr><?php endif; ?>
                <?php foreach ($invoiceNotifications as $notification): ?>
                    <tr><td><?= e($notification['created_at']) ?></td><td><span class="role-badge"><?= e($notification['channel']) ?></span></td><td><?= e($notification['recipient']) ?></td><td><?= e($notification['template']) ?></td><td><span class="status status-<?= e($notification['status']) ?>"><?= e($notification['status']) ?></span></td><td><?= e($notification['attempts']) ?>/<?= e($notification['max_attempts']) ?></td></tr>
                <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Histori pembayaran</h2><p class="muted">Semua pencatatan pembayaran untuk invoice ini.</p></div></div>
        <div class="table-wrap">
            <table><thead><tr><th>Waktu</th><th>Nominal</th><th>Metode</th><th>Referensi</th><th>Dicatat oleh</th></tr></thead><tbody>
                <?php if ($invoicePayments === []): ?><tr><td colspan="5" class="muted">Belum ada pembayaran.</td></tr><?php endif; ?>
                <?php foreach ($invoicePayments as $payment): ?>
                    <tr><td><?= e($payment['paid_at']) ?></td><td><?= e(rupiah($payment['amount'])) ?></td><td><?= e($payment['method']) ?></td><td><?= e($payment['reference_number'] ?: '—') ?></td><td><?= e($payment['recorded_by_name']) ?></td></tr>
                <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <section class="panel">
        <div class="section-heading"><div><h2>Audit invoice</h2><p class="muted">Penerbitan, pembayaran, dan pembatalan yang tercatat.</p></div></div>
        <div class="table-wrap">
            <table><thead><tr><th>Waktu</th><th>Aktivitas</th><th>Oleh</th></tr></thead><tbody>
                <?php if ($invoiceHistory === []): ?><tr><td colspan="3" class="muted">Belum ada audit invoice.</td></tr><?php endif; ?>
                <?php foreach ($invoiceHistory as $history): ?>
                    <tr><td><?= e($history['created_at']) ?></td><td><?= e($history['action']) ?></td><td><?= e($history['actor_name']) ?></td></tr>
                <?php endforeach; ?>
            </tbody></table>
        </div>
    </section>
    <?php
    View::footer();
    exit;
}

if ($path === '/invoices') {
    $customersQuery = $db->prepare("SELECT id, customer_code, name FROM customers WHERE tenant_id = :tenant_id AND status = 'active' ORDER BY name");
    $customersQuery->execute(['tenant_id' => $tenantId]);
    $customers = $customersQuery->fetchAll();

    $search = substr(query_input('q'), 0, 80);
    $statusFilter = query_input('status');
    if (!in_array($statusFilter, ['', 'unpaid', 'paid', 'cancelled', 'overdue'], true)) {
        $statusFilter = '';
    }
    $monthFilter = query_input('month');
    if ($monthFilter !== '' && BillingService::periodStart($monthFilter) === null) {
        $monthFilter = '';
    }
    $where = ['i.tenant_id = :tenant_id'];
    $params = ['tenant_id' => $tenantId];
    if ($search !== '') {
        $where[] = "CONCAT_WS(' ', i.invoice_number, c.customer_code, c.name) LIKE :search";
        $params['search'] = '%' . $search . '%';
    }
    if ($statusFilter === 'overdue') {
        $where[] = "i.status = 'unpaid' AND i.due_date < :today";
        $params['today'] = date('Y-m-d');
    } elseif ($statusFilter !== '') {
        $where[] = 'i.status = :status';
        $params['status'] = $statusFilter;
    }
    if ($monthFilter !== '') {
        $where[] = 'i.billing_period = :billing_period';
        $params['billing_period'] = BillingService::periodStart($monthFilter);
    }
    $whereSql = implode(' AND ', $where);
    $countQuery = $db->prepare(
        'SELECT COUNT(*) FROM invoices i
         INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
         WHERE ' . $whereSql
    );
    $countQuery->execute($params);
    $pagination = new Pagination((int) $countQuery->fetchColumn(), requested_page());
    $invoicesQuery = $db->prepare(
        'SELECT i.id, i.invoice_number, i.period_label, i.billing_period, i.amount,
                i.due_date, i.status, i.source, c.customer_code, c.name AS customer_name
         FROM invoices i INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
         WHERE ' . $whereSql . ' ORDER BY i.id DESC LIMIT :limit OFFSET :offset'
    );
    foreach ($params as $key => $value) {
        $invoicesQuery->bindValue(':' . $key, $value);
    }
    $invoicesQuery->bindValue(':limit', $pagination->perPage, PDO::PARAM_INT);
    $invoicesQuery->bindValue(':offset', $pagination->offset(), PDO::PARAM_INT);
    $invoicesQuery->execute();
    $invoices = $invoicesQuery->fetchAll();
    $defaultMonth = date('Y-m');
    $defaultDueDate = date('Y-m-d', strtotime('+10 days'));
    View::header('Tagihan');
    ?>
    <div class="page-heading"><div><p class="eyebrow">Keuangan</p><h1>Tagihan</h1></div></div>
    <?php if (Auth::canManageBilling()): ?>
        <section class="panel">
            <div class="section-heading"><div><h2>Generator tagihan bulanan</h2><p class="muted">Membuat satu tagihan untuk setiap pelanggan aktif yang memiliki paket aktif.</p></div><span class="secure-badge">Anti duplikat</span></div>
            <form method="post" class="form-grid">
                <?= csrf_field() ?><input type="hidden" name="_action" value="generate">
                <label>Periode<input type="month" name="billing_month" value="<?= e($defaultMonth) ?>" required></label>
                <label>Jatuh tempo<input type="date" name="due_date" value="<?= e($defaultDueDate) ?>" required></label>
                <label>Pajak (%)<input type="number" name="tax_rate" min="0" max="100" step="0.01" value="0" required></label>
                <div class="field-wide"><button class="button button-primary" type="submit">Generate tagihan bulanan</button></div>
            </form>
        </section>
        <section class="panel">
            <h2>Terbitkan tagihan manual</h2>
            <form method="post" class="form-grid">
                <?= csrf_field() ?><input type="hidden" name="_action" value="create">
                <label>Pelanggan<select name="customer_id" required><option value="">Pilih pelanggan</option><?php foreach ($customers as $customer): ?><option value="<?= e($customer['id']) ?>"><?= e($customer['customer_code'] . ' · ' . $customer['name']) ?></option><?php endforeach; ?></select></label>
                <label>Periode<input type="month" name="billing_month" value="<?= e($defaultMonth) ?>" required></label>
                <label>Harga dasar bulanan<input type="number" name="base_amount" min="1" step="1000" required></label>
                <label>Hari aktif prorata (opsional)<input type="number" name="proration_days" min="1" max="31" placeholder="Kosongkan untuk satu bulan penuh"></label>
                <label>Diskon nominal<input type="number" name="discount_amount" min="0" step="1000" value="0" required></label>
                <label>Pajak (%)<input type="number" name="tax_rate" min="0" max="100" step="0.01" value="0" required></label>
                <label>Jatuh tempo<input type="date" name="due_date" value="<?= e($defaultDueDate) ?>" required></label>
                <div class="field-wide"><button class="button button-secondary" type="submit">Terbitkan manual</button></div>
            </form>
        </section>
    <?php endif; ?>
    <section class="panel">
        <div class="section-heading"><div><h2>Daftar tagihan</h2><p class="muted">Cari invoice atau pelanggan, lalu filter status dan periode.</p></div></div>
        <form method="get" class="filter-form">
            <label>Pencarian<input name="q" maxlength="80" value="<?= e($search) ?>" placeholder="Invoice atau pelanggan"></label>
            <label>Status<select name="status"><option value="">Semua status</option><option value="unpaid"<?= $statusFilter === 'unpaid' ? ' selected' : '' ?>>Belum lunas</option><option value="overdue"<?= $statusFilter === 'overdue' ? ' selected' : '' ?>>Jatuh tempo</option><option value="paid"<?= $statusFilter === 'paid' ? ' selected' : '' ?>>Lunas</option><option value="cancelled"<?= $statusFilter === 'cancelled' ? ' selected' : '' ?>>Dibatalkan</option></select></label>
            <label>Periode<input type="month" name="month" value="<?= e($monthFilter) ?>"></label>
            <button class="button button-primary" type="submit">Terapkan</button>
            <a class="button button-secondary" href="/invoices">Reset</a>
        </form>
        <div class="table-wrap">
            <table><thead><tr><th>Invoice</th><th>Pelanggan</th><th>Periode</th><th>Sumber</th><th>Jatuh tempo</th><th>Nominal</th><th>Status</th><th>Aksi</th></tr></thead>
                <tbody>
                <?php if ($invoices === []): ?><tr><td colspan="8" class="muted">Belum ada tagihan yang sesuai.</td></tr><?php endif; ?>
                <?php foreach ($invoices as $invoice): $overdue = $invoice['status'] === 'unpaid' && $invoice['due_date'] < date('Y-m-d'); ?>
                    <tr>
                        <td><a class="table-link" href="/invoices/view?id=<?= e($invoice['id']) ?>"><strong><?= e($invoice['invoice_number']) ?></strong></a></td>
                        <td><?= e($invoice['customer_code']) ?><small><?= e($invoice['customer_name']) ?></small></td>
                        <td><?= e($invoice['period_label']) ?></td><td><span class="role-badge"><?= e($invoice['source']) ?></span></td>
                        <td><?= e($invoice['due_date']) ?></td><td><?= e(rupiah($invoice['amount'])) ?></td>
                        <td><span class="status status-<?= $overdue ? 'overdue' : e($invoice['status']) ?>"><?= $overdue ? 'overdue' : e($invoice['status']) ?></span></td>
                        <td>
                            <?php if ($invoice['status'] === 'unpaid' && Auth::canManageBilling()): ?>
                                <div class="action-group">
                                    <form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="pay"><input type="hidden" name="invoice_id" value="<?= e($invoice['id']) ?>"><button class="button button-small" type="submit">Lunas</button></form>
                                    <form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="_action" value="cancel"><input type="hidden" name="invoice_id" value="<?= e($invoice['id']) ?>"><button class="button button-danger" type="submit">Batalkan</button></form>
                                </div>
                            <?php else: ?>—<?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
        <?php View::pagination($pagination); ?>
    </section>
    <?php
    View::footer();
    exit;
}

http_response_code(404);
View::header('Tidak ditemukan');
?>
<section class="panel empty-state"><p class="eyebrow">404</p><h1>Halaman tidak ditemukan</h1><a class="button button-primary" href="/">Kembali ke dashboard</a></section>
<?php View::footer();
