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

if (!$columnExists($db, 'users', 'must_change_password')) {
    $db->exec("ALTER TABLE users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 0 AFTER status");
}

if (!$columnExists($db, 'tenant_users', 'status')) {
    $db->exec("ALTER TABLE tenant_users ADD COLUMN status ENUM('active', 'disabled') NOT NULL DEFAULT 'active' AFTER role");
}

fwrite(STDOUT, "Database siap.\n");
