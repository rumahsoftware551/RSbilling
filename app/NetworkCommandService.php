<?php

declare(strict_types=1);

final class NetworkCommandService
{
    private const ACTIONS = [
        'health_check',
        'provision_preview',
        'suspend_preview',
        'reactivate_preview',
    ];
    private const MAX_ATTEMPTS = 3;
    private const RETRY_BASE_SECONDS = 30;

    public static function enqueue(
        PDO $db,
        int $tenantId,
        int $userId,
        int $deviceId,
        string $action,
        string $targetReference,
        string $requestToken
    ): array {
        $action = self::validateAction($action);
        $targetReference = self::validateTarget($action, $targetReference);
        if (preg_match('/^[a-f0-9]{32}$/', $requestToken) !== 1) {
            throw new InvalidArgumentException('Token idempotensi perintah tidak valid. Muat ulang halaman dan coba lagi.');
        }

        $deviceQuery = $db->prepare(
            'SELECT id, name, driver, status FROM network_devices
             WHERE id = :id AND tenant_id = :tenant_id LIMIT 1'
        );
        $deviceQuery->execute(['id' => $deviceId, 'tenant_id' => $tenantId]);
        $device = $deviceQuery->fetch();
        if (!$device) {
            throw new DomainException('Perangkat jaringan tidak ditemukan pada ISP ini.');
        }
        if ($device['driver'] !== 'simulator') {
            throw new DomainException('Perintah hanya dapat diantrikan ke simulator; adapter MikroTik nyata tetap nonaktif.');
        }
        if ($device['status'] !== 'active') {
            throw new DomainException('Simulator wajib aktif dan lulus pengujian sebelum menerima perintah.');
        }
        if ($action !== 'health_check') {
            $customerQuery = $db->prepare(
                'SELECT id FROM customers
                 WHERE tenant_id = :tenant_id AND customer_code = :customer_code LIMIT 1'
            );
            $customerQuery->execute([
                'tenant_id' => $tenantId,
                'customer_code' => $targetReference,
            ]);
            if (!$customerQuery->fetch()) {
                throw new DomainException('Kode pelanggan target tidak ditemukan pada ISP ini.');
            }
        }

        $idempotencyKey = hash(
            'sha256',
            implode('|', [$tenantId, $deviceId, $action, $targetReference, $requestToken])
        );
        $commandKey = bin2hex(random_bytes(16));

        try {
            $insert = $db->prepare(
                "INSERT INTO network_commands
                    (tenant_id, network_device_id, command_key, idempotency_key, action,
                     target_reference, status, attempts, max_attempts, available_at, created_by)
                 VALUES
                    (:tenant_id, :network_device_id, :command_key, :idempotency_key, :action,
                     :target_reference, 'pending', 0, :max_attempts, NOW(), :created_by)"
            );
            $insert->execute([
                'tenant_id' => $tenantId,
                'network_device_id' => $deviceId,
                'command_key' => $commandKey,
                'idempotency_key' => $idempotencyKey,
                'action' => $action,
                'target_reference' => $targetReference === '' ? null : $targetReference,
                'max_attempts' => self::MAX_ATTEMPTS,
                'created_by' => $userId,
            ]);

            return [
                'id' => (int) $db->lastInsertId(),
                'command_key' => $commandKey,
                'action' => $action,
                'target_reference' => $targetReference,
                'device_name' => (string) $device['name'],
                'created' => true,
            ];
        } catch (PDOException $exception) {
            if ($exception->getCode() !== '23000') {
                throw $exception;
            }
        }

        $existing = $db->prepare(
            'SELECT c.id, c.command_key, c.action, c.target_reference, d.name AS device_name
             FROM network_commands c
             INNER JOIN network_devices d ON d.id = c.network_device_id AND d.tenant_id = c.tenant_id
             WHERE c.tenant_id = :tenant_id AND c.idempotency_key = :idempotency_key LIMIT 1'
        );
        $existing->execute(['tenant_id' => $tenantId, 'idempotency_key' => $idempotencyKey]);
        $command = $existing->fetch();
        if (!$command) {
            throw new RuntimeException('Perintah duplikat terdeteksi tetapi antrean asal tidak ditemukan.');
        }

        return [
            'id' => (int) $command['id'],
            'command_key' => (string) $command['command_key'],
            'action' => (string) $command['action'],
            'target_reference' => (string) ($command['target_reference'] ?? ''),
            'device_name' => (string) $command['device_name'],
            'created' => false,
        ];
    }

    public static function processDue(
        PDO $db,
        CredentialVault $vault,
        ?int $tenantId = null,
        int $limit = 10
    ): array {
        if ($tenantId !== null && $tenantId < 1) {
            throw new InvalidArgumentException('Tenant worker tidak valid.');
        }
        if ($limit < 1 || $limit > 50) {
            throw new InvalidArgumentException('Batas worker harus berada di antara 1 dan 50.');
        }

        self::recoverStale($db, $tenantId);
        $summary = ['processed' => 0, 'succeeded' => 0, 'retry_scheduled' => 0, 'dead_letter' => 0, 'commands' => []];

        for ($index = 0; $index < $limit; $index++) {
            $command = self::claimNext($db, $tenantId);
            if ($command === null) {
                break;
            }

            $summary['processed']++;
            try {
                if ($command['driver'] !== 'simulator') {
                    throw new DomainException('Driver perangkat tidak diizinkan oleh worker simulator.');
                }
                if ($command['device_status'] !== 'active') {
                    throw new DomainException('Perangkat tidak aktif saat perintah diproses.');
                }

                $credentials = NetworkDeviceService::decryptCredentials(
                    $vault,
                    (int) $command['tenant_id'],
                    $command
                );
                $result = NetworkDeviceSimulator::executeCommand(
                    $command,
                    $credentials,
                    (string) $command['action'],
                    (string) ($command['target_reference'] ?? '')
                );
                self::markSucceeded($db, $command, $result);
                $status = 'succeeded';
            } catch (Throwable $exception) {
                $status = self::markFailed($db, $command, $exception);
            }

            $summary[$status]++;
            $summary['commands'][] = [
                'id' => (int) $command['id'],
                'command_key' => (string) $command['command_key'],
                'status' => $status,
            ];
        }

        return $summary;
    }

    public static function retryDeadLetter(PDO $db, int $tenantId, int $commandId): void
    {
        $update = $db->prepare(
            "UPDATE network_commands
             SET status = 'retry_scheduled', attempts = 0, available_at = NOW(), locked_at = NULL,
                 completed_at = NULL, last_error = NULL, result_payload = NULL
             WHERE id = :id AND tenant_id = :tenant_id AND status = 'dead_letter'"
        );
        $update->execute(['id' => $commandId, 'tenant_id' => $tenantId]);
        if ($update->rowCount() !== 1) {
            throw new DomainException('Hanya perintah dead-letter yang dapat diantrikan ulang.');
        }
    }

    public static function cancel(PDO $db, int $tenantId, int $commandId): void
    {
        $update = $db->prepare(
            "UPDATE network_commands
             SET status = 'cancelled', completed_at = NOW(), locked_at = NULL
             WHERE id = :id AND tenant_id = :tenant_id
               AND status IN ('pending', 'retry_scheduled')"
        );
        $update->execute(['id' => $commandId, 'tenant_id' => $tenantId]);
        if ($update->rowCount() !== 1) {
            throw new DomainException('Perintah tidak ditemukan atau sudah mulai diproses.');
        }
    }

    public static function retryDelaySeconds(int $attempt): int
    {
        if ($attempt < 1) {
            throw new InvalidArgumentException('Nomor percobaan retry tidak valid.');
        }
        return min(self::RETRY_BASE_SECONDS * (2 ** min($attempt - 1, 5)), 900);
    }

    public static function validateAction(string $action): string
    {
        $action = strtolower(trim($action));
        if (!in_array($action, self::ACTIONS, true)) {
            throw new InvalidArgumentException('Jenis perintah jaringan tidak didukung.');
        }
        return $action;
    }

    public static function validateTarget(string $action, string $targetReference): string
    {
        $targetReference = trim($targetReference);
        if (strlen($targetReference) > 120 || str_contains($targetReference, "\0")
            || preg_match('//u', $targetReference) !== 1) {
            throw new InvalidArgumentException('Referensi target perintah tidak valid atau terlalu panjang.');
        }
        if ($action !== 'health_check' && $targetReference === '') {
            throw new InvalidArgumentException('Kode pelanggan atau layanan wajib diisi untuk perintah ini.');
        }
        return $targetReference;
    }

    private static function claimNext(PDO $db, ?int $tenantId): ?array
    {
        $db->beginTransaction();
        try {
            $tenantClause = $tenantId === null ? '' : ' AND c.tenant_id = :tenant_id';
            $query = $db->prepare(
                "SELECT c.id, c.tenant_id, c.network_device_id, c.command_key, c.action,
                        c.target_reference, c.attempts, c.max_attempts,
                        d.device_key, d.name AS device_name, d.driver, d.host, d.port, d.use_tls,
                        d.status AS device_status, d.credential_ciphertext
                 FROM network_commands c
                 INNER JOIN network_devices d
                    ON d.id = c.network_device_id AND d.tenant_id = c.tenant_id
                 WHERE c.status IN ('pending', 'retry_scheduled')
                   AND c.available_at <= NOW(){$tenantClause}
                 ORDER BY c.available_at ASC, c.id ASC
                 LIMIT 1 FOR UPDATE"
            );
            $parameters = $tenantId === null ? [] : ['tenant_id' => $tenantId];
            $query->execute($parameters);
            $command = $query->fetch();
            if (!$command) {
                $db->commit();
                return null;
            }

            $claim = $db->prepare(
                "UPDATE network_commands
                 SET status = 'processing', attempts = attempts + 1, locked_at = NOW()
                 WHERE id = :id AND tenant_id = :tenant_id
                   AND status IN ('pending', 'retry_scheduled')"
            );
            $claim->execute(['id' => $command['id'], 'tenant_id' => $command['tenant_id']]);
            if ($claim->rowCount() !== 1) {
                throw new RuntimeException('Perintah gagal diklaim oleh worker.');
            }
            $command['attempts'] = (int) $command['attempts'] + 1;
            $command['max_attempts'] = (int) $command['max_attempts'];
            $db->commit();
            return $command;
        } catch (Throwable $exception) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $exception;
        }
    }

    private static function markSucceeded(PDO $db, array $command, array $result): void
    {
        $payload = json_encode($result, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (strlen($payload) > 8000) {
            throw new RuntimeException('Hasil simulator melebihi batas penyimpanan aman.');
        }
        $update = $db->prepare(
            "UPDATE network_commands
             SET status = 'succeeded', result_payload = :result_payload, last_error = NULL,
                 locked_at = NULL, completed_at = NOW()
             WHERE id = :id AND tenant_id = :tenant_id AND status = 'processing'"
        );
        $update->execute([
            'result_payload' => $payload,
            'id' => $command['id'],
            'tenant_id' => $command['tenant_id'],
        ]);
        if ($update->rowCount() !== 1) {
            throw new RuntimeException('Hasil perintah simulator gagal disimpan.');
        }
    }

    private static function markFailed(PDO $db, array $command, Throwable $exception): string
    {
        $attempts = (int) $command['attempts'];
        $maxAttempts = (int) $command['max_attempts'];
        $permanent = $exception instanceof DomainException || $exception instanceof InvalidArgumentException;
        $status = ($permanent || $attempts >= $maxAttempts) ? 'dead_letter' : 'retry_scheduled';
        $availableAt = $status === 'retry_scheduled'
            ? date('Y-m-d H:i:s', time() + self::retryDelaySeconds($attempts))
            : date('Y-m-d H:i:s');
        $safeError = $permanent
            ? 'Perintah ditolak oleh kontrol keamanan worker simulator.'
            : 'Eksekusi simulator gagal sementara; detail internal tidak disimpan untuk melindungi secret.';

        $update = $db->prepare(
            "UPDATE network_commands
             SET status = :status, available_at = :available_at, last_error = :last_error,
                 locked_at = NULL, completed_at = :completed_at
             WHERE id = :id AND tenant_id = :tenant_id AND status = 'processing'"
        );
        $update->execute([
            'status' => $status,
            'available_at' => $availableAt,
            'last_error' => $safeError,
            'completed_at' => $status === 'dead_letter' ? $availableAt : null,
            'id' => $command['id'],
            'tenant_id' => $command['tenant_id'],
        ]);
        if ($update->rowCount() !== 1) {
            throw new RuntimeException('Status kegagalan perintah tidak dapat disimpan.');
        }
        return $status;
    }

    private static function recoverStale(PDO $db, ?int $tenantId): void
    {
        $tenantClause = $tenantId === null ? '' : ' AND tenant_id = :tenant_id';
        $retry = $db->prepare(
            "UPDATE network_commands
             SET status = 'retry_scheduled', available_at = NOW(), locked_at = NULL,
                 last_error = 'Worker sebelumnya terhenti; perintah dijadwalkan ulang.'
             WHERE status = 'processing' AND locked_at < (NOW() - INTERVAL 5 MINUTE)
               AND attempts < max_attempts{$tenantClause}"
        );
        $parameters = $tenantId === null ? [] : ['tenant_id' => $tenantId];
        $retry->execute($parameters);

        $deadLetter = $db->prepare(
            "UPDATE network_commands
             SET status = 'dead_letter', locked_at = NULL, completed_at = NOW(),
                 last_error = 'Worker terhenti setelah batas percobaan; perintah dipindahkan ke dead-letter.'
             WHERE status = 'processing' AND locked_at < (NOW() - INTERVAL 5 MINUTE)
               AND attempts >= max_attempts{$tenantClause}"
        );
        $deadLetter->execute($parameters);
    }
}
