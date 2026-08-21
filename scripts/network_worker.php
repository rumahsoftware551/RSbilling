<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

$limit = filter_var(env('NETWORK_WORKER_LIMIT', 20), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 50],
]);
if ($limit === false) {
    throw new InvalidArgumentException('NETWORK_WORKER_LIMIT harus berada di antara 1 dan 50.');
}

$tenantValue = trim((string) env('NETWORK_WORKER_TENANT_ID', ''));
$tenantId = null;
if ($tenantValue !== '') {
    $tenantId = filter_var($tenantValue, FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1],
    ]);
    if ($tenantId === false) {
        throw new InvalidArgumentException('NETWORK_WORKER_TENANT_ID tidak valid.');
    }
}

$result = NetworkCommandService::processDue(
    Database::connection(),
    CredentialVault::fromEnvironment(),
    $tenantId === null ? null : (int) $tenantId,
    (int) $limit
);

fwrite(STDOUT, json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL);
