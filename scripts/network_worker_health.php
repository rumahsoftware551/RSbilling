<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/app/bootstrap.php';

$healthy = NetworkWorkerMonitor::isHealthy(
    Database::connection(),
    NetworkWorkerMonitor::workerKey(),
    90
);

fwrite($healthy ? STDOUT : STDERR, $healthy ? "network-worker healthy\n" : "network-worker unhealthy\n");
exit($healthy ? 0 : 1);
