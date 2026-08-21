<?php

declare(strict_types=1);

final class PaymentReconciliationService
{
    public const MAX_ROWS = 1000;

    private const HEADERS = [
        'external_reference',
        'invoice_number',
        'amount',
        'paid_at',
        'method',
        'payer_name',
    ];

    public static function parseCsv(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new InvalidArgumentException('File rekonsiliasi CSV tidak dapat dibaca.');
        }
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            throw new InvalidArgumentException('File rekonsiliasi CSV tidak dapat dibuka.');
        }

        try {
            $sample = fgets($handle);
            if ($sample === false) {
                throw new InvalidArgumentException('File rekonsiliasi CSV kosong.');
            }
            $delimiter = count(str_getcsv($sample, ';', '"', '\\'))
                > count(str_getcsv($sample, ',', '"', '\\')) ? ';' : ',';
            rewind($handle);

            $headers = fgetcsv($handle, 0, $delimiter, '"', '\\');
            if ($headers === false || $headers === [null]) {
                throw new InvalidArgumentException('Header rekonsiliasi tidak ditemukan.');
            }
            $headers = array_map(static function (mixed $header): string {
                $value = strtolower(trim((string) $header));
                return preg_replace('/^\xEF\xBB\xBF/', '', $value) ?? $value;
            }, $headers);
            if ($headers !== self::HEADERS) {
                throw new InvalidArgumentException(
                    'Urutan header wajib: ' . implode(', ', self::HEADERS) . '.'
                );
            }

            $rows = [];
            $references = [];
            $rowNumber = 1;
            while (($values = fgetcsv($handle, 0, $delimiter, '"', '\\')) !== false) {
                $rowNumber++;
                $values = array_map(static fn (mixed $value): string => trim((string) $value), $values);
                if (count(array_filter($values, static fn (string $value): bool => $value !== '')) === 0) {
                    continue;
                }
                if (count($values) !== count(self::HEADERS)) {
                    throw new InvalidArgumentException('Baris ' . $rowNumber . ' memiliki jumlah kolom yang tidak sesuai.');
                }
                foreach ($values as $value) {
                    if (str_contains($value, "\0") || preg_match('//u', $value) !== 1) {
                        throw new InvalidArgumentException('Baris ' . $rowNumber . ' mengandung karakter tidak valid.');
                    }
                }

                $row = array_combine(self::HEADERS, $values);
                if (!is_array($row)) {
                    throw new InvalidArgumentException('Baris ' . $rowNumber . ' tidak dapat diproses.');
                }
                $row = self::normalizeRow($row, $rowNumber);
                $referenceKey = $row['method'] . '|' . $row['external_reference'];
                if (isset($references[$referenceKey])) {
                    throw new InvalidArgumentException(
                        'Baris ' . $rowNumber . ': referensi dan metode berulang di dalam file.'
                    );
                }
                $references[$referenceKey] = true;
                $rows[] = $row;
                if (count($rows) > self::MAX_ROWS) {
                    throw new InvalidArgumentException('File rekonsiliasi maksimal berisi 1.000 transaksi.');
                }
            }
            if ($rows === []) {
                throw new InvalidArgumentException('File rekonsiliasi tidak memiliki transaksi.');
            }
            return $rows;
        } finally {
            fclose($handle);
        }
    }

    public static function prepareRows(PDO $db, int $tenantId, array $rows): array
    {
        $invoiceNumbers = array_values(array_unique(array_column($rows, 'invoice_number')));
        $params = ['tenant_id' => $tenantId];
        $placeholders = [];
        foreach ($invoiceNumbers as $index => $invoiceNumber) {
            $key = 'invoice_' . $index;
            $placeholders[] = ':' . $key;
            $params[$key] = $invoiceNumber;
        }

        $invoiceMap = [];
        if ($placeholders !== []) {
            $query = $db->prepare(
                'SELECT id, invoice_number, amount, status FROM invoices
                 WHERE tenant_id = :tenant_id AND invoice_number IN (' . implode(', ', $placeholders) . ')
                 FOR UPDATE'
            );
            $query->execute($params);
            foreach ($query as $invoice) {
                $invoiceMap[strtoupper((string) $invoice['invoice_number'])] = $invoice;
            }
        }

        $prepared = [];
        foreach ($rows as $row) {
            $match = self::classifyInvoice($invoiceMap[$row['invoice_number']] ?? null, $row['amount']);
            $prepared[] = array_merge($row, $match);
        }
        return $prepared;
    }

    public static function classifyInvoice(?array $invoice, string $amount): array
    {
        if ($invoice === null) {
            return ['invoice_id' => null, 'match_status' => 'unmatched', 'match_reason' => 'invoice_not_found'];
        }
        $invoiceId = (int) $invoice['id'];
        if ((string) $invoice['status'] !== 'unpaid') {
            return ['invoice_id' => $invoiceId, 'match_status' => 'unmatched', 'match_reason' => 'invoice_not_payable'];
        }
        if (self::decimal((string) $invoice['amount']) !== self::decimal($amount)) {
            return ['invoice_id' => $invoiceId, 'match_status' => 'unmatched', 'match_reason' => 'amount_mismatch'];
        }
        return ['invoice_id' => $invoiceId, 'match_status' => 'matched', 'match_reason' => 'exact_match'];
    }

    public static function rematch(PDO $db, int $tenantId, int $reconciliationId): array
    {
        $query = $db->prepare(
            "SELECT id, invoice_number, amount FROM payment_reconciliations
             WHERE id = :id AND tenant_id = :tenant_id AND match_status = 'unmatched'
             LIMIT 1 FOR UPDATE"
        );
        $query->execute(['id' => $reconciliationId, 'tenant_id' => $tenantId]);
        $item = $query->fetch();
        if (!$item) {
            throw new DomainException('Transaksi tidak ditemukan atau statusnya tidak dapat dicocokkan ulang.');
        }

        $invoiceQuery = $db->prepare(
            'SELECT id, invoice_number, amount, status FROM invoices
             WHERE tenant_id = :tenant_id AND invoice_number = :invoice_number LIMIT 1'
        );
        $invoiceQuery->execute(['tenant_id' => $tenantId, 'invoice_number' => $item['invoice_number']]);
        $invoice = $invoiceQuery->fetch() ?: null;
        $match = self::classifyInvoice($invoice, (string) $item['amount']);
        $update = $db->prepare(
            'UPDATE payment_reconciliations
             SET invoice_id = :invoice_id, match_status = :match_status, match_reason = :match_reason
             WHERE id = :id AND tenant_id = :tenant_id'
        );
        $update->execute([
            'invoice_id' => $match['invoice_id'],
            'match_status' => $match['match_status'],
            'match_reason' => $match['match_reason'],
            'id' => $reconciliationId,
            'tenant_id' => $tenantId,
        ]);
        return $match;
    }

    public static function post(PDO $db, int $tenantId, int $userId, int $reconciliationId): array
    {
        $query = $db->prepare(
            "SELECT r.id, r.invoice_id, r.external_reference, r.amount, r.paid_at, r.method,
                    r.match_status, i.amount AS invoice_amount, i.status AS invoice_status
             FROM payment_reconciliations r
             INNER JOIN invoices i ON i.id = r.invoice_id AND i.tenant_id = r.tenant_id
             WHERE r.id = :id AND r.tenant_id = :tenant_id LIMIT 1 FOR UPDATE"
        );
        $query->execute(['id' => $reconciliationId, 'tenant_id' => $tenantId]);
        $item = $query->fetch();
        if (!$item || $item['match_status'] !== 'matched' || $item['invoice_status'] !== 'unpaid'
            || self::decimal((string) $item['amount']) !== self::decimal((string) $item['invoice_amount'])) {
            throw new DomainException('Transaksi tidak lagi cocok dengan invoice belum lunas.');
        }

        $insert = $db->prepare(
            'INSERT INTO payments
                (tenant_id, invoice_id, amount, method, reference_number, paid_at, recorded_by)
             VALUES
                (:tenant_id, :invoice_id, :amount, :method, :reference_number, :paid_at, :recorded_by)'
        );
        $insert->execute([
            'tenant_id' => $tenantId,
            'invoice_id' => (int) $item['invoice_id'],
            'amount' => $item['amount'],
            'method' => $item['method'],
            'reference_number' => $item['external_reference'],
            'paid_at' => $item['paid_at'],
            'recorded_by' => $userId,
        ]);
        $paymentId = (int) $db->lastInsertId();

        $invoiceUpdate = $db->prepare(
            "UPDATE invoices SET status = 'paid', paid_at = :paid_at
             WHERE id = :invoice_id AND tenant_id = :tenant_id AND status = 'unpaid'"
        );
        $invoiceUpdate->execute([
            'paid_at' => $item['paid_at'],
            'invoice_id' => (int) $item['invoice_id'],
            'tenant_id' => $tenantId,
        ]);
        if ($invoiceUpdate->rowCount() !== 1) {
            throw new RuntimeException('Status invoice gagal diperbarui.');
        }
        $update = $db->prepare(
            "UPDATE payment_reconciliations
             SET match_status = 'posted', payment_id = :payment_id, posted_by = :posted_by, posted_at = NOW()
             WHERE id = :id AND tenant_id = :tenant_id AND match_status = 'matched'"
        );
        $update->execute([
            'payment_id' => $paymentId,
            'posted_by' => $userId,
            'id' => $reconciliationId,
            'tenant_id' => $tenantId,
        ]);
        if ($update->rowCount() !== 1) {
            throw new RuntimeException('Status rekonsiliasi gagal diperbarui.');
        }

        return [
            'payment_id' => $paymentId,
            'invoice_id' => (int) $item['invoice_id'],
            'reference' => (string) $item['external_reference'],
            'method' => (string) $item['method'],
        ];
    }

    public static function ignore(PDO $db, int $tenantId, int $reconciliationId): void
    {
        $update = $db->prepare(
            "UPDATE payment_reconciliations SET match_status = 'ignored'
             WHERE id = :id AND tenant_id = :tenant_id AND match_status IN ('matched', 'unmatched')"
        );
        $update->execute(['id' => $reconciliationId, 'tenant_id' => $tenantId]);
        if ($update->rowCount() !== 1) {
            throw new DomainException('Transaksi tidak ditemukan atau tidak dapat diabaikan.');
        }
    }

    public static function invalidateInvoiceMatches(
        PDO $db,
        int $tenantId,
        int $invoiceId,
        string $reason = 'invoice_not_payable'
    ): int {
        if (!in_array($reason, ['invoice_not_payable', 'amount_mismatch'], true)) {
            throw new InvalidArgumentException('Alasan invalidasi rekonsiliasi tidak valid.');
        }
        $update = $db->prepare(
            "UPDATE payment_reconciliations
             SET match_status = 'unmatched', match_reason = :match_reason
             WHERE invoice_id = :invoice_id AND tenant_id = :tenant_id AND match_status = 'matched'"
        );
        $update->execute([
            'match_reason' => $reason,
            'invoice_id' => $invoiceId,
            'tenant_id' => $tenantId,
        ]);
        return $update->rowCount();
    }

    private static function normalizeRow(array $row, int $rowNumber): array
    {
        $reference = strtoupper(trim((string) $row['external_reference']));
        $invoiceNumber = strtoupper(trim((string) $row['invoice_number']));
        $method = strtolower(trim((string) $row['method']));
        $payerName = trim((string) $row['payer_name']);
        if (!preg_match('/^[A-Z0-9._\/-]{2,100}$/', $reference)) {
            throw new InvalidArgumentException('Baris ' . $rowNumber . ': external_reference tidak valid.');
        }
        if (!preg_match('/^[A-Z0-9._-]{2,50}$/', $invoiceNumber)) {
            throw new InvalidArgumentException('Baris ' . $rowNumber . ': invoice_number tidak valid.');
        }
        if (!preg_match('/^[a-z0-9._-]{2,40}$/', $method)) {
            throw new InvalidArgumentException('Baris ' . $rowNumber . ': method tidak valid.');
        }
        if (strlen($payerName) > 120) {
            throw new InvalidArgumentException('Baris ' . $rowNumber . ': payer_name maksimal 120 karakter.');
        }

        $amountInput = str_replace(',', '.', trim((string) $row['amount']));
        if (!preg_match('/^[0-9]{1,13}(?:\.[0-9]{1,2})?$/', $amountInput)) {
            throw new InvalidArgumentException('Baris ' . $rowNumber . ': amount tidak valid.');
        }
        $amount = self::decimal($amountInput);
        if ($amount === '0.00') {
            throw new InvalidArgumentException('Baris ' . $rowNumber . ': amount harus lebih dari nol.');
        }

        $paidAtInput = trim((string) $row['paid_at']);
        $paidAt = null;
        foreach ([
            ['!Y-m-d H:i:s', 'Y-m-d H:i:s'],
            ['!Y-m-d\TH:i:s', 'Y-m-d\TH:i:s'],
            ['!Y-m-d', 'Y-m-d'],
        ] as [$inputFormat, $comparisonFormat]) {
            $date = DateTimeImmutable::createFromFormat($inputFormat, $paidAtInput);
            if ($date !== false && $date->format($comparisonFormat) === $paidAtInput) {
                $paidAt = $date->format('Y-m-d H:i:s');
                break;
            }
        }
        if ($paidAt === null || $paidAt > date('Y-m-d H:i:s', strtotime('+5 minutes'))) {
            throw new InvalidArgumentException('Baris ' . $rowNumber . ': paid_at tidak valid atau berada di masa depan.');
        }

        return [
            '_row' => $rowNumber,
            'external_reference' => $reference,
            'invoice_number' => $invoiceNumber,
            'amount' => $amount,
            'paid_at' => $paidAt,
            'method' => $method,
            'payer_name' => $payerName !== '' ? $payerName : null,
        ];
    }

    private static function decimal(string $amount): string
    {
        $amount = trim($amount);
        if (preg_match('/^[0-9]+(?:\.[0-9]{1,2})?$/', $amount) !== 1) {
            throw new InvalidArgumentException('Nominal desimal tidak valid.');
        }

        [$whole, $fraction] = array_pad(explode('.', $amount, 2), 2, '');
        $whole = ltrim($whole, '0');
        return ($whole !== '' ? $whole : '0') . '.' . str_pad($fraction, 2, '0');
    }
}
