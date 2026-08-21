<?php

declare(strict_types=1);

final class NetworkDeviceService
{
    private const DRIVERS = ['simulator', 'mikrotik'];

    public static function create(
        PDO $db,
        CredentialVault $vault,
        int $tenantId,
        int $userId,
        array $configuration,
        array $credentials
    ): array {
        $configuration = self::validateConfiguration($configuration);
        $credentials = self::validateCredentials($credentials);
        $deviceKey = bin2hex(random_bytes(16));
        $ciphertext = $vault->encrypt($credentials, self::aad($tenantId, $deviceKey));

        try {
            $insert = $db->prepare(
                "INSERT INTO network_devices
                    (tenant_id, device_key, name, driver, host, port, use_tls, credential_ciphertext,
                     credential_key_version, status, created_by, updated_by)
                 VALUES
                    (:tenant_id, :device_key, :name, :driver, :host, :port, :use_tls,
                     :credential_ciphertext, 1, 'inactive', :created_by, :updated_by)"
            );
            $insert->execute([
                'tenant_id' => $tenantId,
                'device_key' => $deviceKey,
                'name' => $configuration['name'],
                'driver' => $configuration['driver'],
                'host' => $configuration['host'],
                'port' => $configuration['port'],
                'use_tls' => $configuration['use_tls'] ? 1 : 0,
                'credential_ciphertext' => $ciphertext,
                'created_by' => $userId,
                'updated_by' => $userId,
            ]);
        } catch (PDOException $exception) {
            if ($exception->getCode() === '23000') {
                throw new DomainException('Nama perangkat sudah digunakan pada ISP ini.', 0, $exception);
            }
            throw $exception;
        }

        return [
            'id' => (int) $db->lastInsertId(),
            'name' => $configuration['name'],
            'driver' => $configuration['driver'],
            'host' => $configuration['host'],
            'port' => $configuration['port'],
            'use_tls' => $configuration['use_tls'],
        ];
    }

    public static function rotateCredentials(
        PDO $db,
        CredentialVault $vault,
        int $tenantId,
        int $userId,
        int $deviceId,
        array $credentials
    ): void {
        $credentials = self::validateCredentials($credentials);
        $query = $db->prepare(
            'SELECT id, device_key FROM network_devices
             WHERE id = :id AND tenant_id = :tenant_id LIMIT 1 FOR UPDATE'
        );
        $query->execute(['id' => $deviceId, 'tenant_id' => $tenantId]);
        $device = $query->fetch();
        if (!$device) {
            throw new DomainException('Perangkat jaringan tidak ditemukan pada ISP ini.');
        }

        $ciphertext = $vault->encrypt(
            $credentials,
            self::aad($tenantId, (string) $device['device_key'])
        );
        $update = $db->prepare(
            "UPDATE network_devices
             SET credential_ciphertext = :credential_ciphertext, credential_key_version = 1,
                 updated_by = :updated_by, last_test_status = 'never', last_test_message = NULL,
                 last_tested_at = NULL, status = 'inactive'
             WHERE id = :id AND tenant_id = :tenant_id"
        );
        $update->execute([
            'credential_ciphertext' => $ciphertext,
            'updated_by' => $userId,
            'id' => $deviceId,
            'tenant_id' => $tenantId,
        ]);
        if ($update->rowCount() !== 1) {
            throw new RuntimeException('Rotasi credential vault gagal disimpan.');
        }
    }

    public static function testSimulator(
        PDO $db,
        CredentialVault $vault,
        int $tenantId,
        int $userId,
        int $deviceId
    ): array {
        $query = $db->prepare(
            'SELECT id, device_key, name, driver, host, port, use_tls, credential_ciphertext, status
             FROM network_devices
             WHERE id = :id AND tenant_id = :tenant_id LIMIT 1 FOR UPDATE'
        );
        $query->execute(['id' => $deviceId, 'tenant_id' => $tenantId]);
        $device = $query->fetch();
        if (!$device) {
            throw new DomainException('Perangkat jaringan tidak ditemukan pada ISP ini.');
        }
        if ($device['driver'] !== 'simulator') {
            throw new DomainException('Adapter MikroTik nyata belum diaktifkan; tidak ada koneksi jaringan yang dilakukan.');
        }
        if ($device['status'] === 'disabled') {
            throw new DomainException('Aktifkan kembali perangkat sebelum menjalankan simulator.');
        }

        $credentials = $vault->decrypt(
            (string) $device['credential_ciphertext'],
            self::aad($tenantId, (string) $device['device_key'])
        );
        $result = NetworkDeviceSimulator::probe($device, $credentials);
        $message = substr((string) $result['message'], 0, 190);

        $update = $db->prepare(
            "UPDATE network_devices
             SET status = 'active', last_test_status = 'success', last_test_message = :message,
                 last_tested_at = NOW(), updated_by = :updated_by
             WHERE id = :id AND tenant_id = :tenant_id"
        );
        $update->execute([
            'message' => $message,
            'updated_by' => $userId,
            'id' => $deviceId,
            'tenant_id' => $tenantId,
        ]);
        if ($update->rowCount() !== 1) {
            throw new RuntimeException('Hasil simulator gagal disimpan.');
        }

        return $result;
    }

    public static function setDisabled(
        PDO $db,
        int $tenantId,
        int $userId,
        int $deviceId,
        bool $disabled
    ): string {
        $status = $disabled ? 'disabled' : 'inactive';
        $update = $db->prepare(
            'UPDATE network_devices SET status = :status, updated_by = :updated_by
             WHERE id = :id AND tenant_id = :tenant_id'
        );
        $update->execute([
            'status' => $status,
            'updated_by' => $userId,
            'id' => $deviceId,
            'tenant_id' => $tenantId,
        ]);
        if ($update->rowCount() !== 1) {
            throw new DomainException('Perangkat tidak ditemukan atau statusnya sudah sama.');
        }
        return $status;
    }

    public static function validateConfiguration(array $configuration): array
    {
        $name = trim((string) ($configuration['name'] ?? ''));
        $driver = strtolower(trim((string) ($configuration['driver'] ?? '')));
        $host = strtolower(rtrim(trim((string) ($configuration['host'] ?? '')), '.'));
        $port = filter_var($configuration['port'] ?? null, FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 65535],
        ]);
        $useTls = (bool) ($configuration['use_tls'] ?? false);

        if ($name === '' || strlen($name) > 120 || preg_match('//u', $name) !== 1) {
            throw new InvalidArgumentException('Nama perangkat wajib diisi, valid, dan maksimal 120 karakter.');
        }
        if (!in_array($driver, self::DRIVERS, true)) {
            throw new InvalidArgumentException('Driver perangkat tidak didukung.');
        }
        $hostIsValid = filter_var($host, FILTER_VALIDATE_IP) !== false
            || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false;
        if ($host === '' || strlen($host) > 253 || !$hostIsValid) {
            throw new InvalidArgumentException('Host perangkat harus berupa alamat IP atau hostname yang valid.');
        }
        if ($port === false) {
            throw new InvalidArgumentException('Port perangkat harus berada pada rentang 1–65535.');
        }

        return [
            'name' => $name,
            'driver' => $driver,
            'host' => $host,
            'port' => (int) $port,
            'use_tls' => $useTls,
        ];
    }

    public static function validateCredentials(array $credentials): array
    {
        $username = trim((string) ($credentials['username'] ?? ''));
        $password = (string) ($credentials['password'] ?? '');
        if ($username === '' || strlen($username) > 120 || str_contains($username, "\0")
            || preg_match('//u', $username) !== 1) {
            throw new InvalidArgumentException('Username perangkat wajib diisi dan maksimal 120 karakter.');
        }
        if (strlen($password) < 8 || strlen($password) > 255 || str_contains($password, "\0")
            || preg_match('//u', $password) !== 1) {
            throw new InvalidArgumentException('Password perangkat wajib berisi 8–255 karakter valid.');
        }

        return ['username' => $username, 'password' => $password];
    }

    private static function aad(int $tenantId, string $deviceKey): string
    {
        if ($tenantId < 1 || preg_match('/^[a-f0-9]{32}$/', $deviceKey) !== 1) {
            throw new InvalidArgumentException('Konteks credential vault tidak valid.');
        }
        return 'rsbilling|network-device|v1|' . $tenantId . '|' . $deviceKey;
    }
}
