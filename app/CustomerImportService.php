<?php

declare(strict_types=1);

final class CustomerImportService
{
    public const MAX_ROWS = 1000;

    private const ALLOWED_HEADERS = [
        'customer_code',
        'name',
        'phone',
        'email',
        'address',
        'plan_code',
        'status',
    ];

    private const REQUIRED_HEADERS = ['customer_code', 'name'];

    public static function parse(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new InvalidArgumentException('File CSV tidak dapat dibaca.');
        }

        $handle = fopen($path, 'rb');
        if ($handle === false) {
            throw new InvalidArgumentException('File CSV tidak dapat dibuka.');
        }

        try {
            $sample = fgets($handle);
            if ($sample === false) {
                throw new InvalidArgumentException('File CSV kosong.');
            }
            $delimiter = count(str_getcsv($sample, ';', '"', '\\'))
                > count(str_getcsv($sample, ',', '"', '\\')) ? ';' : ',';
            rewind($handle);

            $headers = fgetcsv($handle, 0, $delimiter, '"', '\\');
            if ($headers === false || $headers === [null]) {
                throw new InvalidArgumentException('Header CSV tidak ditemukan.');
            }
            $headers = array_map(static function (mixed $header): string {
                $value = strtolower(trim((string) $header));
                return preg_replace('/^\xEF\xBB\xBF/', '', $value) ?? $value;
            }, $headers);

            if (count($headers) !== count(array_unique($headers))) {
                throw new InvalidArgumentException('Header CSV tidak boleh berulang.');
            }
            foreach (self::REQUIRED_HEADERS as $required) {
                if (!in_array($required, $headers, true)) {
                    throw new InvalidArgumentException('Header wajib tidak tersedia: ' . $required . '.');
                }
            }
            $unsupported = array_diff($headers, self::ALLOWED_HEADERS);
            if ($unsupported !== []) {
                throw new InvalidArgumentException('Header CSV tidak dikenal: ' . implode(', ', $unsupported) . '.');
            }

            $rows = [];
            $rowNumber = 1;
            while (($values = fgetcsv($handle, 0, $delimiter, '"', '\\')) !== false) {
                $rowNumber++;
                $values = array_map(static fn (mixed $value): string => trim((string) $value), $values);
                if (count(array_filter($values, static fn (string $value): bool => $value !== '')) === 0) {
                    continue;
                }
                if (count($values) > count($headers)) {
                    throw new InvalidArgumentException('Baris ' . $rowNumber . ' memiliki kolom berlebih.');
                }
                $values = array_pad($values, count($headers), '');
                foreach ($values as $value) {
                    if (str_contains($value, "\0") || preg_match('//u', $value) !== 1) {
                        throw new InvalidArgumentException('Baris ' . $rowNumber . ' mengandung karakter yang tidak valid.');
                    }
                }

                $row = array_combine($headers, $values);
                if (!is_array($row)) {
                    throw new InvalidArgumentException('Baris ' . $rowNumber . ' tidak dapat diproses.');
                }
                foreach (self::ALLOWED_HEADERS as $header) {
                    $row[$header] ??= '';
                }
                $row['_row'] = $rowNumber;
                $rows[] = $row;
                if (count($rows) > self::MAX_ROWS) {
                    throw new InvalidArgumentException('File CSV maksimal berisi 1.000 pelanggan.');
                }
            }

            if ($rows === []) {
                throw new InvalidArgumentException('File CSV tidak memiliki data pelanggan.');
            }

            return $rows;
        } finally {
            fclose($handle);
        }
    }
}
