<?php

declare(strict_types=1);

final class BillingService
{
    private const MONTH_NAMES = [
        1 => 'Januari',
        2 => 'Februari',
        3 => 'Maret',
        4 => 'April',
        5 => 'Mei',
        6 => 'Juni',
        7 => 'Juli',
        8 => 'Agustus',
        9 => 'September',
        10 => 'Oktober',
        11 => 'November',
        12 => 'Desember',
    ];

    public static function periodStart(string $month): ?string
    {
        if (!preg_match('/^\d{4}-(0[1-9]|1[0-2])$/', $month)) {
            return null;
        }

        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $month . '-01');
        return $date && $date->format('Y-m') === $month ? $date->format('Y-m-d') : null;
    }

    public static function monthLabel(string $month): ?string
    {
        $periodStart = self::periodStart($month);
        if ($periodStart === null) {
            return null;
        }

        $date = new DateTimeImmutable($periodStart);
        return self::MONTH_NAMES[(int) $date->format('n')] . ' ' . $date->format('Y');
    }

    public static function invoiceNumber(string $month, int $customerId, string $customerCode): string
    {
        $normalizedCode = preg_replace('/[^A-Z0-9._-]/', '-', strtoupper($customerCode)) ?: 'CUSTOMER';
        return substr(
            sprintf('INV-%s-%d-%s', str_replace('-', '', $month), $customerId, $normalizedCode),
            0,
            50
        );
    }

    public static function generateMonthly(PDO $db, int $tenantId, string $month, string $dueDate): array
    {
        $periodStart = self::periodStart($month);
        $periodLabel = self::monthLabel($month);
        if ($periodStart === null || $periodLabel === null) {
            throw new InvalidArgumentException('Periode tagihan bulanan tidak valid.');
        }
        $dueDateValue = DateTimeImmutable::createFromFormat('!Y-m-d', $dueDate);
        if (!$dueDateValue || $dueDateValue->format('Y-m-d') !== $dueDate || $dueDate < $periodStart) {
            throw new InvalidArgumentException('Jatuh tempo tagihan bulanan tidak valid.');
        }

        $customersQuery = $db->prepare(
            "SELECT c.id, c.customer_code, p.price
             FROM customers c
             LEFT JOIN plans p ON p.id = c.plan_id
                AND p.tenant_id = c.tenant_id AND p.status = 'active'
             WHERE c.tenant_id = :tenant_id AND c.status = 'active'
             ORDER BY c.id"
        );
        $customersQuery->execute(['tenant_id' => $tenantId]);

        $insert = $db->prepare(
            "INSERT INTO invoices
                (tenant_id, customer_id, invoice_number, period_label, billing_period, amount, due_date, source)
             VALUES
                (:tenant_id, :customer_id, :invoice_number, :period_label, :billing_period, :amount, :due_date, 'monthly')"
        );

        $result = ['created' => 0, 'existing' => 0, 'without_plan' => 0];
        foreach ($customersQuery as $customer) {
            if ($customer['price'] === null || (float) $customer['price'] <= 0) {
                $result['without_plan']++;
                continue;
            }

            try {
                $insert->execute([
                    'tenant_id' => $tenantId,
                    'customer_id' => (int) $customer['id'],
                    'invoice_number' => self::invoiceNumber(
                        $month,
                        (int) $customer['id'],
                        (string) $customer['customer_code']
                    ),
                    'period_label' => $periodLabel,
                    'billing_period' => $periodStart,
                    'amount' => $customer['price'],
                    'due_date' => $dueDate,
                ]);
                $result['created']++;
            } catch (PDOException $exception) {
                if ($exception->getCode() === '23000') {
                    $result['existing']++;
                    continue;
                }
                throw $exception;
            }
        }

        return $result;
    }
}
