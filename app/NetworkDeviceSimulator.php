<?php

declare(strict_types=1);

final class NetworkDeviceSimulator
{
    private const COMMANDS = [
        'health_check',
        'provision_preview',
        'suspend_preview',
        'reactivate_preview',
    ];

    public static function probe(array $device, array $credentials): array
    {
        if (($device['driver'] ?? null) !== 'simulator') {
            throw new DomainException('Probe simulator hanya berlaku untuk perangkat simulator.');
        }
        if (!is_string($credentials['username'] ?? null) || $credentials['username'] === ''
            || !is_string($credentials['password'] ?? null) || $credentials['password'] === '') {
            throw new RuntimeException('Kredensial simulator tidak lengkap.');
        }

        $deviceKey = (string) ($device['device_key'] ?? '');
        $identitySuffix = strtoupper(substr(hash('sha256', $deviceKey), 0, 8));
        $latency = 2 + (hexdec(substr(hash('sha256', $deviceKey . '|latency'), 0, 2)) % 18);

        return [
            'status' => 'success',
            'identity' => 'RSB-SIM-' . $identitySuffix,
            'version' => 'RouterOS 7.x simulator',
            'transport' => ((int) ($device['use_tls'] ?? 0) === 1) ? 'api-ssl-simulated' : 'api-simulated',
            'latency_ms' => $latency,
            'capabilities' => [
                'health_check',
                'provision_preview',
                'suspend_preview',
                'reactivate_preview',
            ],
            'message' => 'Simulator siap; vault berhasil dibuka tanpa koneksi jaringan eksternal.',
        ];
    }

    public static function executeCommand(
        array $device,
        array $credentials,
        string $action,
        string $targetReference = ''
    ): array {
        if (!in_array($action, self::COMMANDS, true)) {
            throw new DomainException('Perintah tidak didukung oleh simulator.');
        }
        $targetReference = trim($targetReference);
        if ($action !== 'health_check' && $targetReference === '') {
            throw new DomainException('Target simulator wajib tersedia untuk perintah ini.');
        }

        $probe = self::probe($device, $credentials);
        $fingerprint = strtoupper(substr(hash(
            'sha256',
            implode('|', [(string) ($device['device_key'] ?? ''), $action, $targetReference])
        ), 0, 12));
        $messages = [
            'health_check' => 'Health check simulator berhasil tanpa koneksi eksternal.',
            'provision_preview' => 'Preview provisioning berhasil; tidak ada akun jaringan yang dibuat.',
            'suspend_preview' => 'Preview suspend berhasil; tidak ada sesi pelanggan yang diputus.',
            'reactivate_preview' => 'Preview reaktivasi berhasil; tidak ada konfigurasi jaringan yang diubah.',
        ];

        return [
            'status' => 'success',
            'action' => $action,
            'target_reference' => $targetReference === '' ? null : $targetReference,
            'command_reference' => 'SIM-' . $fingerprint,
            'device_identity' => $probe['identity'],
            'changed_network' => false,
            'message' => $messages[$action],
        ];
    }
}
