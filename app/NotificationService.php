<?php

declare(strict_types=1);

final class NotificationService
{
    private const CHANNELS = ['whatsapp', 'email'];

    public static function normalizeRecipient(string $channel, string $recipient): string
    {
        self::assertChannel($channel);
        $recipient = trim($recipient);

        if ($channel === 'email') {
            $recipient = strtolower($recipient);
            if (!filter_var($recipient, FILTER_VALIDATE_EMAIL) || strlen($recipient) > 190) {
                throw new InvalidArgumentException('Alamat email pelanggan tidak valid.');
            }
            return $recipient;
        }

        $digits = preg_replace('/\D+/', '', $recipient) ?? '';
        if (str_starts_with($digits, '0')) {
            $digits = '62' . substr($digits, 1);
        }
        if (!preg_match('/^[1-9][0-9]{7,14}$/', $digits)) {
            throw new InvalidArgumentException('Nomor WhatsApp pelanggan tidak valid.');
        }
        return $digits;
    }

    public static function composeInvoice(array $invoice, string $channel): array
    {
        self::assertChannel($channel);
        $required = ['tenant_name', 'customer_name', 'invoice_number', 'period_label', 'amount', 'due_date'];
        foreach ($required as $key) {
            if (!array_key_exists($key, $invoice) || trim((string) $invoice[$key]) === '') {
                throw new InvalidArgumentException('Data invoice untuk notifikasi belum lengkap.');
            }
        }

        $overdue = (string) $invoice['due_date'] < date('Y-m-d');
        $template = $overdue ? 'invoice_overdue' : 'invoice_reminder';
        $amount = 'Rp' . number_format((float) $invoice['amount'], 0, ',', '.');
        $subject = $overdue
            ? 'Pengingat keterlambatan ' . $invoice['invoice_number']
            : 'Pengingat tagihan ' . $invoice['invoice_number'];
        $message = implode("\n", [
            'Yth. ' . trim((string) $invoice['customer_name']) . ',',
            '',
            ($overdue ? 'Tagihan internet Anda telah melewati jatuh tempo.' : 'Berikut pengingat tagihan internet Anda.'),
            'ISP: ' . trim((string) $invoice['tenant_name']),
            'Invoice: ' . trim((string) $invoice['invoice_number']),
            'Periode: ' . trim((string) $invoice['period_label']),
            'Total: ' . $amount,
            'Jatuh tempo: ' . trim((string) $invoice['due_date']),
            '',
            'Abaikan pesan ini apabila pembayaran sudah dilakukan. Hubungi ISP untuk konfirmasi.',
        ]);

        return [
            'template' => $template,
            'subject' => $channel === 'email' ? substr($subject, 0, 190) : null,
            'message' => $message,
        ];
    }

    public static function enqueueInvoice(
        PDO $db,
        int $tenantId,
        int $userId,
        int $invoiceId,
        string $channel
    ): array {
        self::assertChannel($channel);
        $query = $db->prepare(
            "SELECT i.id, i.invoice_number, i.period_label, i.amount, i.due_date, i.status,
                    c.id AS customer_id, c.name AS customer_name, c.phone, c.email,
                    t.name AS tenant_name
             FROM invoices i
             INNER JOIN customers c ON c.id = i.customer_id AND c.tenant_id = i.tenant_id
             INNER JOIN tenants t ON t.id = i.tenant_id
             WHERE i.id = :invoice_id AND i.tenant_id = :tenant_id AND i.status = 'unpaid'
             LIMIT 1"
        );
        $query->execute(['invoice_id' => $invoiceId, 'tenant_id' => $tenantId]);
        $invoice = $query->fetch();
        if (!$invoice) {
            throw new DomainException('Invoice belum lunas tidak ditemukan pada ISP ini.');
        }

        $recipient = self::normalizeRecipient(
            $channel,
            $channel === 'email' ? (string) $invoice['email'] : (string) $invoice['phone']
        );
        $content = self::composeInvoice($invoice, $channel);
        $idempotencyKey = hash('sha256', implode('|', [
            'invoice-notification-v1',
            $tenantId,
            $invoiceId,
            $channel,
            $content['template'],
            $recipient,
            $invoice['amount'],
            $invoice['due_date'],
            hash('sha256', $content['message']),
        ]));

        try {
            $insert = $db->prepare(
                'INSERT INTO notification_outbox
                    (tenant_id, invoice_id, customer_id, channel, recipient, template, subject,
                     message, status, idempotency_key, created_by, available_at)
                 VALUES
                    (:tenant_id, :invoice_id, :customer_id, :channel, :recipient, :template, :subject,
                     :message, \'pending\', :idempotency_key, :created_by, NOW())'
            );
            $insert->execute([
                'tenant_id' => $tenantId,
                'invoice_id' => $invoiceId,
                'customer_id' => (int) $invoice['customer_id'],
                'channel' => $channel,
                'recipient' => $recipient,
                'template' => $content['template'],
                'subject' => $content['subject'],
                'message' => $content['message'],
                'idempotency_key' => $idempotencyKey,
                'created_by' => $userId,
            ]);
            return [
                'id' => (int) $db->lastInsertId(),
                'created' => true,
                'status' => 'pending',
                'recipient' => $recipient,
                'template' => $content['template'],
            ];
        } catch (PDOException $exception) {
            if ($exception->getCode() !== '23000') {
                throw $exception;
            }
        }

        $existing = $db->prepare(
            'SELECT id, status, recipient, template FROM notification_outbox
             WHERE tenant_id = :tenant_id AND idempotency_key = :idempotency_key LIMIT 1'
        );
        $existing->execute(['tenant_id' => $tenantId, 'idempotency_key' => $idempotencyKey]);
        $notification = $existing->fetch();
        if (!$notification) {
            throw new RuntimeException('Status antrean notifikasi tidak dapat dipastikan.');
        }
        return array_merge($notification, ['id' => (int) $notification['id'], 'created' => false]);
    }

    public static function cancel(PDO $db, int $tenantId, int $notificationId): void
    {
        $update = $db->prepare(
            "UPDATE notification_outbox SET status = 'cancelled', locked_at = NULL
             WHERE id = :id AND tenant_id = :tenant_id AND status IN ('pending', 'failed')"
        );
        $update->execute(['id' => $notificationId, 'tenant_id' => $tenantId]);
        if ($update->rowCount() !== 1) {
            throw new DomainException('Notifikasi tidak ditemukan atau statusnya tidak dapat dibatalkan.');
        }
    }

    public static function retry(PDO $db, int $tenantId, int $notificationId): void
    {
        $update = $db->prepare(
            "UPDATE notification_outbox n
             INNER JOIN invoices i ON i.id = n.invoice_id AND i.tenant_id = n.tenant_id
             SET n.status = 'pending', n.attempts = 0, n.available_at = NOW(),
                 n.locked_at = NULL, n.last_error = NULL
             WHERE n.id = :id AND n.tenant_id = :tenant_id
               AND n.status IN ('failed', 'cancelled') AND i.status = 'unpaid'"
        );
        $update->execute(['id' => $notificationId, 'tenant_id' => $tenantId]);
        if ($update->rowCount() !== 1) {
            throw new DomainException('Notifikasi tidak ditemukan atau belum dapat diantrekan ulang.');
        }
    }

    public static function cancelInvoiceNotifications(PDO $db, int $tenantId, int $invoiceId): int
    {
        $update = $db->prepare(
            "UPDATE notification_outbox SET status = 'cancelled', locked_at = NULL
             WHERE invoice_id = :invoice_id AND tenant_id = :tenant_id
               AND status IN ('pending', 'failed')"
        );
        $update->execute(['invoice_id' => $invoiceId, 'tenant_id' => $tenantId]);
        return $update->rowCount();
    }

    private static function assertChannel(string $channel): void
    {
        if (!in_array($channel, self::CHANNELS, true)) {
            throw new InvalidArgumentException('Kanal notifikasi tidak valid.');
        }
    }
}
