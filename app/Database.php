<?php

declare(strict_types=1);

final class Database
{
    private static ?PDO $connection = null;

    public static function connection(): PDO
    {
        if (self::$connection instanceof PDO) {
            return self::$connection;
        }

        $host = (string) env('DB_HOST', '127.0.0.1');
        $port = (int) env('DB_PORT', 3306);
        $database = (string) env('DB_DATABASE', 'rsbilling');
        $username = (string) env('DB_USERNAME', 'rsbilling');
        $password = (string) env('DB_PASSWORD', '');

        if ($password === '') {
            throw new RuntimeException('DB_PASSWORD belum dikonfigurasi.');
        }

        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $database);
        self::$connection = new PDO($dsn, $username, $password, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_STRINGIFY_FETCHES => false,
        ]);

        $timezone = new DateTimeZone(date_default_timezone_get());
        $offsetSeconds = $timezone->getOffset(new DateTimeImmutable('now', $timezone));
        $sign = $offsetSeconds < 0 ? '-' : '+';
        $absoluteOffset = abs($offsetSeconds);
        $offset = sprintf('%s%02d:%02d', $sign, intdiv($absoluteOffset, 3600), intdiv($absoluteOffset % 3600, 60));
        self::$connection->exec('SET time_zone = ' . self::$connection->quote($offset));

        return self::$connection;
    }
}
