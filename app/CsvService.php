<?php

declare(strict_types=1);

final class CsvService
{
    public static function safeCell(mixed $value): string
    {
        $cell = str_replace("\0", '', (string) $value);
        if ($cell !== '' && preg_match('/^[\x01-\x20]*[=+\-@]/', $cell) === 1) {
            return "'" . $cell;
        }

        return $cell;
    }

    public static function writeRow(mixed $stream, array $values): void
    {
        if (!is_resource($stream)) {
            throw new InvalidArgumentException('Stream CSV tidak valid.');
        }
        $safeValues = array_map([self::class, 'safeCell'], $values);
        if (fputcsv($stream, $safeValues, ',', '"', '\\', "\r\n") === false) {
            throw new RuntimeException('Baris CSV gagal ditulis.');
        }
    }
}
