<?php

declare(strict_types=1);

final class NetworkWorkerMonitor
{
    private const STATUSES = ['starting', 'running', 'stopping', 'stopped', 'failed'];
    private const HEALTHY_MAX_AGE_SECONDS = 90;

    public static function workerKey(): string
    {
        $identity = trim((string) env('NETWORK_WORKER_ID', gethostname() ?: 'network-worker'));
        return self::keyForIdentity($identity);
    }

    public static function keyForIdentity(string $identity): string
    {
        $identity = trim($identity);
        if ($identity === '' || strlen($identity) > 190 || str_contains($identity, "\0")
            || preg_match('//u', $identity) !== 1) {
            throw new InvalidArgumentException('Identitas worker jaringan tidak valid.');
        }
        return hash('sha256', 'rsbilling|network-worker|v1|' . $identity);
    }

    public static function beat(
        PDO $db,
        string $workerKey,
        string $status,
        int $batchProcessed = 0,
        ?string $lastError = null
    ): void {
        if (preg_match('/^[a-f0-9]{64}$/', $workerKey) !== 1) {
            throw new InvalidArgumentException('Kunci heartbeat worker tidak valid.');
        }
        if (!in_array($status, self::STATUSES, true)) {
            throw new InvalidArgumentException('Status heartbeat worker tidak valid.');
        }
        if ($batchProcessed < 0 || $batchProcessed > 50) {
            throw new InvalidArgumentException('Jumlah batch heartbeat tidak valid.');
        }
        if ($lastError !== null && strlen($lastError) > 190) {
            throw new InvalidArgumentException('Pesan heartbeat terlalu panjang.');
        }

        $stoppedAt = in_array($status, ['stopped', 'failed'], true) ? date('Y-m-d H:i:s') : null;
        $statement = $db->prepare(
            "INSERT INTO network_worker_heartbeats
                (worker_key, status, last_seen_at, last_batch_processed, total_processed,
                 last_error, started_at, stopped_at)
             VALUES
                (:worker_key, :status, NOW(), :last_batch_processed, :total_processed,
                 :last_error, NOW(), :stopped_at)
             ON DUPLICATE KEY UPDATE
                status = VALUES(status), last_seen_at = NOW(),
                last_batch_processed = VALUES(last_batch_processed),
                total_processed = total_processed + VALUES(last_batch_processed),
                last_error = VALUES(last_error),
                started_at = IF(VALUES(status) = 'starting', NOW(), started_at),
                stopped_at = VALUES(stopped_at)"
        );
        $statement->execute([
            'worker_key' => $workerKey,
            'status' => $status,
            'last_batch_processed' => $batchProcessed,
            'total_processed' => $batchProcessed,
            'last_error' => $lastError,
            'stopped_at' => $stoppedAt,
        ]);
    }

    public static function isHealthy(
        PDO $db,
        string $workerKey,
        int $maxAgeSeconds = self::HEALTHY_MAX_AGE_SECONDS
    ): bool
    {
        if (preg_match('/^[a-f0-9]{64}$/', $workerKey) !== 1
            || $maxAgeSeconds < 5 || $maxAgeSeconds > 300) {
            return false;
        }
        $threshold = date('Y-m-d H:i:s', time() - $maxAgeSeconds);
        $query = $db->prepare(
            "SELECT COUNT(*) FROM network_worker_heartbeats
             WHERE worker_key = :worker_key AND status = 'running'
               AND last_seen_at >= :threshold"
        );
        $query->execute(['worker_key' => $workerKey, 'threshold' => $threshold]);
        return (int) $query->fetchColumn() === 1;
    }

    public static function recent(PDO $db, int $limit = 5): array
    {
        if ($limit < 1 || $limit > 20) {
            throw new InvalidArgumentException('Batas monitoring worker tidak valid.');
        }
        $query = $db->prepare(
            'SELECT worker_key, status, last_seen_at, last_batch_processed, total_processed,
                    last_error, started_at, stopped_at,
                    TIMESTAMPDIFF(SECOND, last_seen_at, NOW()) AS heartbeat_age_seconds
             FROM network_worker_heartbeats
             ORDER BY last_seen_at DESC LIMIT :limit'
        );
        $query->bindValue('limit', $limit, PDO::PARAM_INT);
        $query->execute();
        $workers = $query->fetchAll();
        foreach ($workers as &$worker) {
            $age = max(0, (int) $worker['heartbeat_age_seconds']);
            $worker['heartbeat_age_seconds'] = $age;
            $worker['healthy'] = $worker['status'] === 'running'
                && $age <= self::HEALTHY_MAX_AGE_SECONDS;
        }
        unset($worker);
        return $workers;
    }

    public static function cleanup(PDO $db): void
    {
        $db->exec(
            "DELETE FROM network_worker_heartbeats
             WHERE last_seen_at < (NOW() - INTERVAL 30 DAY)"
        );
    }
}
