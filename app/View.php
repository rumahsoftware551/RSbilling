<?php

declare(strict_types=1);

final class View
{
    public static function header(string $title, bool $showNavigation = true): void
    {
        $user = Auth::user();
        $flash = pull_flash();
        ?>
<!doctype html>
<html lang="id">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="color-scheme" content="light">
    <title><?= e($title) ?> · RS Billing</title>
    <link rel="stylesheet" href="/assets/app.css">
</head>
<body>
<?php if ($showNavigation): ?>
    <header class="topbar">
        <a class="brand" href="/">RS Billing</a>
        <nav aria-label="Navigasi utama">
            <a href="/">Dashboard</a>
            <a href="/customers">Pelanggan</a>
            <a href="/plans">Paket</a>
            <a href="/invoices">Tagihan</a>
            <?php if (Auth::canManageBilling()): ?><a href="/notifications">Notifikasi</a><?php endif; ?>
            <?php if (Auth::canViewReports()): ?><a href="/reports">Laporan</a><?php endif; ?>
            <?php if (Auth::canManageUsers()): ?><a href="/users">Pengguna</a><?php endif; ?>
            <a href="/account">Akun Saya</a>
        </nav>
        <div class="account">
            <span><strong><?= e($user['tenant_name'] ?? '') ?></strong><small><?= e($user['name'] ?? '') ?></small></span>
            <form method="post" action="/logout">
                <?= csrf_field() ?>
                <button class="button button-ghost" type="submit">Keluar</button>
            </form>
        </div>
    </header>
<?php endif; ?>
<main class="container<?= $showNavigation ? '' : ' container-auth' ?>">
<?php if ($flash): ?>
    <div class="alert alert-<?= e($flash['type']) ?>" role="status"><?= e($flash['message']) ?></div>
<?php endif; ?>
        <?php
    }

    public static function footer(): void
    {
        ?>
</main>
<footer>RS Billing · Fondasi billing ISP multi-tenant</footer>
</body>
</html>
        <?php
    }

    public static function pagination(Pagination $pagination): void
    {
        if ($pagination->total === 0) {
            return;
        }
        ?>
        <div class="pagination-wrap">
            <span>Menampilkan <?= e($pagination->from()) ?>–<?= e($pagination->to()) ?> dari <?= e($pagination->total) ?></span>
            <nav class="pagination" aria-label="Navigasi halaman">
                <?php if ($pagination->page > 1): ?>
                    <a href="<?= e($pagination->url($pagination->page - 1)) ?>">Sebelumnya</a>
                <?php else: ?>
                    <span class="is-disabled">Sebelumnya</span>
                <?php endif; ?>
                <strong><?= e($pagination->page) ?> / <?= e($pagination->totalPages) ?></strong>
                <?php if ($pagination->page < $pagination->totalPages): ?>
                    <a href="<?= e($pagination->url($pagination->page + 1)) ?>">Berikutnya</a>
                <?php else: ?>
                    <span class="is-disabled">Berikutnya</span>
                <?php endif; ?>
            </nav>
        </div>
        <?php
    }
}
