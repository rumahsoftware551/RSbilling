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

fwrite(STDOUT, "Database siap.\n");
