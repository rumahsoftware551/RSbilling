<?php

declare(strict_types=1);

final class CredentialVault
{
    private const CIPHER = 'aes-256-gcm';
    private const KEY_BYTES = 32;
    private const NONCE_BYTES = 12;
    private const TAG_BYTES = 16;

    private function __construct(private readonly string $key)
    {
    }

    public static function isConfigured(): bool
    {
        if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt')) {
            return false;
        }

        try {
            self::fromEnvironment();
            return true;
        } catch (Throwable) {
            return false;
        }
    }

    public static function fromEnvironment(): self
    {
        try {
            return self::fromBase64((string) env('APP_KEY', ''));
        } catch (InvalidArgumentException $exception) {
            throw new DomainException(
                'APP_KEY belum valid. Buat kunci acak 32-byte sebelum menyimpan perangkat jaringan.',
                0,
                $exception
            );
        }
    }

    public static function fromBase64(string $encodedKey): self
    {
        if (!function_exists('openssl_encrypt') || !function_exists('openssl_decrypt')) {
            throw new RuntimeException('Ekstensi OpenSSL PHP wajib tersedia untuk credential vault.');
        }

        $encodedKey = trim($encodedKey);
        if (str_starts_with($encodedKey, 'base64:')) {
            $encodedKey = substr($encodedKey, 7);
        }
        $key = base64_decode($encodedKey, true);
        if ($key === false || strlen($key) !== self::KEY_BYTES) {
            throw new InvalidArgumentException('Kunci vault wajib berupa base64 dari tepat 32 byte acak.');
        }

        return new self($key);
    }

    public function encrypt(array $credentials, string $aad): string
    {
        if ($credentials === [] || $aad === '') {
            throw new InvalidArgumentException('Kredensial dan konteks enkripsi wajib tersedia.');
        }

        $plaintext = json_encode($credentials, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $nonce = random_bytes(self::NONCE_BYTES);
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad,
            self::TAG_BYTES
        );
        if ($ciphertext === false || strlen($tag) !== self::TAG_BYTES) {
            throw new RuntimeException('Kredensial perangkat gagal dienkripsi.');
        }

        return json_encode([
            'v' => 1,
            'n' => base64_encode($nonce),
            'c' => base64_encode($ciphertext),
            't' => base64_encode($tag),
        ], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    public function decrypt(string $payload, string $aad): array
    {
        if ($payload === '' || strlen($payload) > 8192 || $aad === '') {
            throw new RuntimeException('Payload credential vault tidak valid.');
        }

        try {
            $decoded = json_decode($payload, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Payload credential vault rusak.', 0, $exception);
        }
        if (!is_array($decoded) || ($decoded['v'] ?? null) !== 1
            || !is_string($decoded['n'] ?? null)
            || !is_string($decoded['c'] ?? null)
            || !is_string($decoded['t'] ?? null)) {
            throw new RuntimeException('Versi atau struktur credential vault tidak didukung.');
        }

        $nonce = base64_decode($decoded['n'], true);
        $ciphertext = base64_decode($decoded['c'], true);
        $tag = base64_decode($decoded['t'], true);
        if ($nonce === false || strlen($nonce) !== self::NONCE_BYTES
            || $ciphertext === false || $tag === false || strlen($tag) !== self::TAG_BYTES) {
            throw new RuntimeException('Komponen credential vault tidak valid.');
        }

        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $this->key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $aad
        );
        if ($plaintext === false) {
            throw new RuntimeException('Kredensial tidak dapat dibuka atau autentikasinya gagal.');
        }

        try {
            $credentials = json_decode($plaintext, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException $exception) {
            throw new RuntimeException('Isi credential vault tidak valid.', 0, $exception);
        }
        if (!is_array($credentials)) {
            throw new RuntimeException('Isi credential vault tidak didukung.');
        }

        return $credentials;
    }
}
