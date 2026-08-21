<?php

declare(strict_types=1);

final class NetworkDeviceSimulator
{
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
}
