<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

$schema = file_get_contents(__DIR__ . '/schema.sql');
if ($schema === false) {
    throw new RuntimeException('File schema.sql tidak dapat dibaca.');
}

$statements = preg_split('/;\s*(?:\r?\n|$)/', $schema) ?: [];
$db = Database::connection();
foreach ($statements as $statement) {
    $statement = trim($statement);
    if ($statement !== '') {
        $db->exec($statement);
    }
}

$columnExists = static function (PDO $connection, string $table, string $column): bool {
    $query = $connection->prepare(
        'SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name AND COLUMN_NAME = :column_name'
    );
    $query->execute(['table_name' => $table, 'column_name' => $column]);
    return (int) $query->fetchColumn() > 0;
};

$indexExists = static function (PDO $connection, string $table, string $index): bool {
    $query = $connection->prepare(
        'SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS
         WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name AND INDEX_NAME = :index_name'
    );
    $query->execute(['table_name' => $table, 'index_name' => $index]);
    return (int) $query->fetchColumn() > 0;
};

if (!$columnExists($db, 'users', 'must_change_password')) {
    $db->exec("ALTER TABLE users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0 AFTER status");
}

if (!$columnExists($db, 'tenant_users', 'status')) {
    $db->exec("ALTER TABLE tenant_users ADD COLUMN status ENUM('active', 'disabled') NOT NULL DEFAULT 'active' AFTER role");
}

if (!$columnExists($db, 'invoices', 'billing_period')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN billing_period DATE NULL AFTER period_label");
}

if (!$columnExists($db, 'invoices', 'source')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN source ENUM('manual', 'monthly') NOT NULL DEFAULT 'manual' AFTER due_date");
}

if (!$columnExists($db, 'invoices', 'base_amount')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN base_amount DECIMAL(15,2) NOT NULL DEFAULT 0 AFTER billing_period");
}

if (!$columnExists($db, 'invoices', 'subtotal')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN subtotal DECIMAL(15,2) NOT NULL DEFAULT 0 AFTER base_amount");
}

if (!$columnExists($db, 'invoices', 'discount_amount')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN discount_amount DECIMAL(15,2) NOT NULL DEFAULT 0 AFTER subtotal");
}

if (!$columnExists($db, 'invoices', 'tax_rate')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN tax_rate DECIMAL(5,2) NOT NULL DEFAULT 0 AFTER discount_amount");
}

if (!$columnExists($db, 'invoices', 'tax_amount')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN tax_amount DECIMAL(15,2) NOT NULL DEFAULT 0 AFTER tax_rate");
}

if (!$columnExists($db, 'invoices', 'penalty_amount')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN penalty_amount DECIMAL(15,2) NOT NULL DEFAULT 0 AFTER tax_amount");
}

if (!$columnExists($db, 'invoices', 'proration_days')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN proration_days SMALLINT UNSIGNED NULL AFTER penalty_amount");
}

if (!$columnExists($db, 'invoices', 'proration_total_days')) {
    $db->exec("ALTER TABLE invoices ADD COLUMN proration_total_days SMALLINT UNSIGNED NULL AFTER proration_days");
}

$db->exec(
    'UPDATE invoices SET base_amount = amount, subtotal = amount
     WHERE base_amount = 0 AND subtotal = 0 AND amount > 0
       AND discount_amount = 0 AND tax_amount = 0 AND penalty_amount = 0'
);

if (!$indexExists($db, 'invoices', 'invoices_tenant_customer_period_unique')) {
    $db->exec(
        'ALTER TABLE invoices ADD UNIQUE KEY invoices_tenant_customer_period_unique
         (tenant_id, customer_id, billing_period)'
    );
}

fwrite(STDOUT, "Database siap.\n");
