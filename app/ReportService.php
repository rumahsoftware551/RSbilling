<?php

declare(strict_types=1);

final class ReportService
{
    private const MAX_RANGE_DAYS = 366;

    public static function normalizeRange(string $dateFrom, string $dateTo): array
    {
        $from = DateTimeImmutable::createFromFormat('!Y-m-d', $dateFrom);
        $to = DateTimeImmutable::createFromFormat('!Y-m-d', $dateTo);
        if (!$from || $from->format('Y-m-d') !== $dateFrom
            || !$to || $to->format('Y-m-d') !== $dateTo) {
            throw new InvalidArgumentException('Tanggal awal atau akhir laporan tidak valid.');
        }
        if ($from > $to) {
            throw new InvalidArgumentException('Tanggal awal laporan tidak boleh melewati tanggal akhir.');
        }

        $inclusiveDays = (int) $from->diff($to)->days + 1;
        if ($inclusiveDays > self::MAX_RANGE_DAYS) {
            throw new InvalidArgumentException('Rentang laporan maksimal 366 hari.');
        }

        return [
            'date_from' => $dateFrom,
            'date_to' => $dateTo,
            'start_at' => $dateFrom . ' 00:00:00',
            'end_before' => $to->modify('+1 day')->format('Y-m-d') . ' 00:00:00',
            'inclusive_days' => $inclusiveDays,
        ];
    }

    public static function agingBoundaries(string $today): array
    {
        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $today);
        if (!$date || $date->format('Y-m-d') !== $today) {
            throw new InvalidArgumentException('Tanggal aging piutang tidak valid.');
        }

        return [
            'today' => $today,
            'day_30' => $date->modify('-30 days')->format('Y-m-d'),
            'day_60' => $date->modify('-60 days')->format('Y-m-d'),
            'day_90' => $date->modify('-90 days')->format('Y-m-d'),
        ];
    }
}
