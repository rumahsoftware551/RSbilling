<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

if (!function_exists('pcntl_async_signals') || !function_exists('pcntl_signal')) {
    throw new RuntimeException('Ekstensi PCNTL wajib tersedia untuk graceful shutdown worker.');
}

$limit = filter_var(env('NETWORK_WORKER_LIMIT', 20), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 50],
]);
$pollSeconds = filter_var(env('NETWORK_WORKER_POLL_SECONDS', 5), FILTER_VALIDATE_INT, [
    'options' => ['min_range' => 1, 'max_range' => 30],
]);
if ($limit === false || $pollSeconds === false) {
    throw new InvalidArgumentException('Konfigurasi limit atau interval worker tidak valid.');
}

$shutdownRequested = false;
pcntl_async_signals(true);
pcntl_signal(SIGTERM, static function () use (&$shutdownRequested): void {
    $shutdownRequested = true;
});
pcntl_signal(SIGINT, static function () use (&$shutdownRequested): void {
    $shutdownRequested = true;
});

$db = Database::connection();
$workerKey = NetworkWorkerMonitor::workerKey();
$failed = false;
NetworkWorkerMonitor::cleanup($db);
NetworkWorkerMonitor::beat($db, $workerKey, 'starting');

try {
    $vault = CredentialVault::fromEnvironment();
    NetworkWorkerMonitor::beat($db, $workerKey, 'running');
    while (!$shutdownRequested) {
        $summary = NetworkCommandService::processDue($db, $vault, null, (int) $limit);
        NetworkWorkerMonitor::beat($db, $workerKey, 'running', (int) $summary['processed']);

        if ((int) $summary['processed'] > 0) {
            fwrite(STDOUT, json_encode([
                'processed' => $summary['processed'],
                'succeeded' => $summary['succeeded'],
                'retry_scheduled' => $summary['retry_scheduled'],
                'dead_letter' => $summary['dead_letter'],
            ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL);
        }
        if ((int) $summary['processed'] >= (int) $limit) {
            continue;
        }
        for ($second = 0; $second < (int) $pollSeconds && !$shutdownRequested; $second++) {
            sleep(1);
        }
    }
} catch (Throwable) {
    $failed = true;
    try {
        NetworkWorkerMonitor::beat(
            $db,
            $workerKey,
            'failed',
            0,
            'Worker berhenti karena kegagalan internal; detail secret tidak disimpan.'
        );
    } catch (Throwable) {
        // Docker restart policy tetap menangani kegagalan ketika database tidak dapat dihubungi.
    }
    throw new RuntimeException('Worker berhenti karena kegagalan internal.');
} finally {
    if (!$failed) {
        try {
            NetworkWorkerMonitor::beat($db, $workerKey, 'stopping');
            NetworkWorkerMonitor::beat($db, $workerKey, 'stopped');
        } catch (Throwable) {
            fwrite(STDERR, "Heartbeat akhir worker tidak dapat disimpan.\n");
        }
    }
}
