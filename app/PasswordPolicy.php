<?php

declare(strict_types=1);

final class PasswordPolicy
{
    private const MIN_LENGTH = 12;
    private const MAX_LENGTH = 128;

    private const BLOCKED_PASSWORDS = [
        'GANTI_DENGAN_PASSWORD_ADMIN_KUAT',
        'ChangeMe123!',
        'Admin@12345',
        'Password123!',
    ];

    public static function isAcceptable(string $password): bool
    {
        $length = strlen($password);

        return $length >= self::MIN_LENGTH
            && $length <= self::MAX_LENGTH
            && !in_array($password, self::BLOCKED_PASSWORDS, true);
    }

    public static function requirement(): string
    {
        return 'Password wajib unik, sepanjang 12–128 karakter, dan bukan password contoh.';
    }
}
