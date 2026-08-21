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

    public static function daysInMonth(string $month): ?int
    {
        $periodStart = self::periodStart($month);
        if ($periodStart === null) {
            return null;
        }

        return (int) (new DateTimeImmutable($periodStart))->format('t');
    }

    public static function calculateTotals(
        float $baseAmount,
        float $taxRate = 0,
        float $discountAmount = 0,
        ?int $prorationDays = null,
        ?int $totalDays = null
    ): array {
        if (!is_finite($baseAmount) || $baseAmount <= 0 || $baseAmount > 9999999999999.99) {
            throw new InvalidArgumentException('Harga dasar tagihan tidak valid.');
        }
        if (!is_finite($taxRate) || $taxRate < 0 || $taxRate > 100) {
            throw new InvalidArgumentException('Persentase pajak harus berada di antara 0 dan 100.');
        }
        if (!is_finite($discountAmount) || $discountAmount < 0) {
            throw new InvalidArgumentException('Nominal diskon tidak valid.');
        }

        if ($prorationDays !== null) {
            if ($totalDays === null || $totalDays < 1 || $prorationDays < 1 || $prorationDays > $totalDays) {
                throw new InvalidArgumentException('Jumlah hari prorata tidak valid untuk periode tersebut.');
            }
            $subtotal = round($baseAmount * $prorationDays / $totalDays, 2);
        } else {
            $subtotal = round($baseAmount, 2);
        }

        $discountAmount = round($discountAmount, 2);
        if ($discountAmount > $subtotal) {
            throw new InvalidArgumentException('Diskon tidak boleh melebihi subtotal tagihan.');
        }

        $taxableAmount = round($subtotal - $discountAmount, 2);
        $taxAmount = round($taxableAmount * $taxRate / 100, 2);
        $amount = round($taxableAmount + $taxAmount, 2);
        if ($amount <= 0 || $amount > 9999999999999.99) {
            throw new InvalidArgumentException('Total tagihan berada di luar batas yang diizinkan.');
        }

        return [
            'base_amount' => round($baseAmount, 2),
            'subtotal' => $subtotal,
            'discount_amount' => $discountAmount,
            'tax_rate' => round($taxRate, 2),
            'tax_amount' => $taxAmount,
            'penalty_amount' => 0.0,
            'proration_days' => $prorationDays,
            'proration_total_days' => $prorationDays !== null ? $totalDays : null,
            'amount' => $amount,
        ];
    }

    public static function totalWithPenalty(
        float $subtotal,
        float $discountAmount,
        float $taxAmount,
        float $penaltyAmount
    ): float {
        if (!is_finite($penaltyAmount) || $penaltyAmount < 0 || $penaltyAmount > 9999999999999.99) {
            throw new InvalidArgumentException('Nominal denda tidak valid.');
        }

        $amount = round($subtotal - $discountAmount + $taxAmount + $penaltyAmount, 2);
        if ($amount <= 0 || $amount > 9999999999999.99) {
            throw new InvalidArgumentException('Total tagihan setelah denda tidak valid.');
        }

        return $amount;
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

    public static function generateMonthly(
        PDO $db,
        int $tenantId,
        string $month,
        string $dueDate,
        float $taxRate = 0
    ): array
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
        self::calculateTotals(1, $taxRate);

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
                (tenant_id, customer_id, invoice_number, period_label, billing_period,
                 base_amount, subtotal, discount_amount, tax_rate, tax_amount, penalty_amount, amount, due_date, source)
             VALUES
                (:tenant_id, :customer_id, :invoice_number, :period_label, :billing_period,
                 :base_amount, :subtotal, :discount_amount, :tax_rate, :tax_amount, :penalty_amount, :amount, :due_date, 'monthly')"
        );

        $result = ['created' => 0, 'existing' => 0, 'without_plan' => 0];
        foreach ($customersQuery as $customer) {
            if ($customer['price'] === null || (float) $customer['price'] <= 0) {
                $result['without_plan']++;
                continue;
            }

            try {
                $totals = self::calculateTotals((float) $customer['price'], $taxRate);
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
                    'base_amount' => $totals['base_amount'],
                    'subtotal' => $totals['subtotal'],
                    'discount_amount' => $totals['discount_amount'],
                    'tax_rate' => $totals['tax_rate'],
                    'tax_amount' => $totals['tax_amount'],
                    'penalty_amount' => $totals['penalty_amount'],
                    'amount' => $totals['amount'],
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
