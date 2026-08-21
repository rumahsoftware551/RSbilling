CREATE TABLE IF NOT EXISTS tenants (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(120) NOT NULL,
    slug VARCHAR(80) NOT NULL,
    status ENUM('active', 'suspended') NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY tenants_slug_unique (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(190) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    must_change_password TINYINT(1) NOT NULL DEFAULT 0,
    last_login_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY users_email_unique (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tenant_users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    role ENUM('owner', 'admin', 'billing', 'support', 'viewer') NOT NULL DEFAULT 'viewer',
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY tenant_users_membership_unique (tenant_id, user_id),
    KEY tenant_users_user_idx (user_id),
    CONSTRAINT tenant_users_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT tenant_users_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_attempts (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    attempt_key CHAR(64) NOT NULL,
    attempted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY login_attempts_lookup_idx (attempt_key, attempted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS plans (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    code VARCHAR(30) NOT NULL,
    name VARCHAR(120) NOT NULL,
    speed_label VARCHAR(80) NOT NULL,
    price DECIMAL(15,2) NOT NULL,
    status ENUM('active', 'inactive') NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY plans_tenant_code_unique (tenant_id, code),
    KEY plans_tenant_status_idx (tenant_id, status),
    CONSTRAINT plans_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS customers (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    plan_id BIGINT UNSIGNED NULL,
    customer_code VARCHAR(30) NOT NULL,
    name VARCHAR(120) NOT NULL,
    phone VARCHAR(30) NOT NULL DEFAULT '',
    email VARCHAR(190) NULL,
    address TEXT NULL,
    status ENUM('active', 'suspended', 'terminated') NOT NULL DEFAULT 'active',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY customers_tenant_code_unique (tenant_id, customer_code),
    KEY customers_tenant_status_idx (tenant_id, status),
    KEY customers_plan_idx (plan_id),
    CONSTRAINT customers_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT customers_plan_fk FOREIGN KEY (plan_id) REFERENCES plans (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS invoices (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    customer_id BIGINT UNSIGNED NOT NULL,
    invoice_number VARCHAR(50) NOT NULL,
    period_label VARCHAR(40) NOT NULL,
    billing_period DATE NULL,
    base_amount DECIMAL(15,2) NOT NULL DEFAULT 0,
    subtotal DECIMAL(15,2) NOT NULL DEFAULT 0,
    discount_amount DECIMAL(15,2) NOT NULL DEFAULT 0,
    tax_rate DECIMAL(5,2) NOT NULL DEFAULT 0,
    tax_amount DECIMAL(15,2) NOT NULL DEFAULT 0,
    penalty_amount DECIMAL(15,2) NOT NULL DEFAULT 0,
    proration_days SMALLINT UNSIGNED NULL,
    proration_total_days SMALLINT UNSIGNED NULL,
    amount DECIMAL(15,2) NOT NULL,
    due_date DATE NOT NULL,
    source ENUM('manual', 'monthly') NOT NULL DEFAULT 'manual',
    status ENUM('draft', 'unpaid', 'paid', 'cancelled') NOT NULL DEFAULT 'unpaid',
    paid_at TIMESTAMP NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY invoices_tenant_number_unique (tenant_id, invoice_number),
    UNIQUE KEY invoices_tenant_customer_period_unique (tenant_id, customer_id, billing_period),
    KEY invoices_tenant_status_due_idx (tenant_id, status, due_date),
    KEY invoices_tenant_created_idx (tenant_id, created_at),
    KEY invoices_customer_idx (customer_id),
    CONSTRAINT invoices_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT invoices_customer_fk FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS payments (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    invoice_id BIGINT UNSIGNED NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    method VARCHAR(40) NOT NULL DEFAULT 'manual',
    reference_number VARCHAR(100) NULL,
    paid_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    recorded_by BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY payments_tenant_paid_idx (tenant_id, paid_at),
    KEY payments_invoice_idx (invoice_id),
    CONSTRAINT payments_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT payments_invoice_fk FOREIGN KEY (invoice_id) REFERENCES invoices (id) ON DELETE RESTRICT,
    CONSTRAINT payments_user_fk FOREIGN KEY (recorded_by) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS payment_reconciliations (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    invoice_id BIGINT UNSIGNED NULL,
    payment_id BIGINT UNSIGNED NULL,
    external_reference VARCHAR(100) NOT NULL,
    invoice_number VARCHAR(50) NOT NULL,
    amount DECIMAL(15,2) NOT NULL,
    paid_at DATETIME NOT NULL,
    method VARCHAR(40) NOT NULL,
    payer_name VARCHAR(120) NULL,
    match_status ENUM('matched', 'unmatched', 'posted', 'ignored') NOT NULL,
    match_reason VARCHAR(40) NOT NULL,
    import_batch CHAR(32) NOT NULL,
    source_file VARCHAR(120) NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    posted_by BIGINT UNSIGNED NULL,
    posted_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY payment_reconciliations_tenant_method_reference_unique
        (tenant_id, method, external_reference),
    KEY payment_reconciliations_tenant_status_idx (tenant_id, match_status, created_at),
    KEY payment_reconciliations_batch_idx (tenant_id, import_batch),
    KEY payment_reconciliations_invoice_idx (invoice_id),
    CONSTRAINT payment_reconciliations_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT payment_reconciliations_invoice_fk FOREIGN KEY (invoice_id) REFERENCES invoices (id) ON DELETE RESTRICT,
    CONSTRAINT payment_reconciliations_payment_fk FOREIGN KEY (payment_id) REFERENCES payments (id) ON DELETE RESTRICT,
    CONSTRAINT payment_reconciliations_created_user_fk FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT payment_reconciliations_posted_user_fk FOREIGN KEY (posted_by) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notification_outbox (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    invoice_id BIGINT UNSIGNED NULL,
    customer_id BIGINT UNSIGNED NOT NULL,
    channel ENUM('whatsapp', 'email') NOT NULL,
    recipient VARCHAR(190) NOT NULL,
    template VARCHAR(80) NOT NULL,
    subject VARCHAR(190) NULL,
    message TEXT NOT NULL,
    status ENUM('pending', 'processing', 'sent', 'failed', 'cancelled') NOT NULL DEFAULT 'pending',
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 3,
    available_at DATETIME NOT NULL,
    locked_at DATETIME NULL,
    sent_at DATETIME NULL,
    provider_reference VARCHAR(190) NULL,
    last_error VARCHAR(500) NULL,
    idempotency_key CHAR(64) NOT NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY notification_outbox_tenant_idempotency_unique (tenant_id, idempotency_key),
    KEY notification_outbox_tenant_queue_idx (tenant_id, status, available_at),
    KEY notification_outbox_invoice_idx (invoice_id),
    KEY notification_outbox_customer_idx (customer_id),
    CONSTRAINT notification_outbox_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT notification_outbox_invoice_fk FOREIGN KEY (invoice_id) REFERENCES invoices (id) ON DELETE RESTRICT,
    CONSTRAINT notification_outbox_customer_fk FOREIGN KEY (customer_id) REFERENCES customers (id) ON DELETE RESTRICT,
    CONSTRAINT notification_outbox_user_fk FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS network_devices (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    device_key CHAR(32) NOT NULL,
    name VARCHAR(120) NOT NULL,
    driver ENUM('simulator', 'mikrotik') NOT NULL DEFAULT 'simulator',
    host VARCHAR(253) NOT NULL,
    port SMALLINT UNSIGNED NOT NULL DEFAULT 8729,
    use_tls TINYINT(1) NOT NULL DEFAULT 1,
    credential_ciphertext TEXT NOT NULL,
    credential_key_version SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    status ENUM('inactive', 'active', 'disabled') NOT NULL DEFAULT 'inactive',
    last_test_status ENUM('never', 'success', 'failed') NOT NULL DEFAULT 'never',
    last_test_message VARCHAR(190) NULL,
    last_tested_at DATETIME NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    updated_by BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY network_devices_tenant_name_unique (tenant_id, name),
    UNIQUE KEY network_devices_tenant_device_key_unique (tenant_id, device_key),
    KEY network_devices_tenant_status_idx (tenant_id, status),
    CONSTRAINT network_devices_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT network_devices_created_user_fk FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT,
    CONSTRAINT network_devices_updated_user_fk FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS network_commands (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    network_device_id BIGINT UNSIGNED NOT NULL,
    command_key CHAR(32) NOT NULL,
    idempotency_key CHAR(64) NOT NULL,
    action ENUM('health_check', 'provision_preview', 'suspend_preview', 'reactivate_preview') NOT NULL,
    target_reference VARCHAR(120) NULL,
    status ENUM('pending', 'processing', 'succeeded', 'retry_scheduled', 'dead_letter', 'cancelled')
        NOT NULL DEFAULT 'pending',
    attempts SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    max_attempts SMALLINT UNSIGNED NOT NULL DEFAULT 3,
    available_at DATETIME NOT NULL,
    locked_at DATETIME NULL,
    completed_at DATETIME NULL,
    result_payload TEXT NULL,
    last_error VARCHAR(500) NULL,
    created_by BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY network_commands_tenant_command_unique (tenant_id, command_key),
    UNIQUE KEY network_commands_tenant_idempotency_unique (tenant_id, idempotency_key),
    KEY network_commands_tenant_queue_idx (tenant_id, status, available_at),
    KEY network_commands_device_idx (network_device_id),
    CONSTRAINT network_commands_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT network_commands_device_fk FOREIGN KEY (network_device_id) REFERENCES network_devices (id) ON DELETE RESTRICT,
    CONSTRAINT network_commands_created_user_fk FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS network_worker_heartbeats (
    worker_key CHAR(64) NOT NULL,
    status ENUM('starting', 'running', 'stopping', 'stopped', 'failed') NOT NULL DEFAULT 'starting',
    last_seen_at DATETIME NOT NULL,
    last_batch_processed SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    total_processed BIGINT UNSIGNED NOT NULL DEFAULT 0,
    last_error VARCHAR(190) NULL,
    started_at DATETIME NOT NULL,
    stopped_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (worker_key),
    KEY network_worker_heartbeats_status_seen_idx (status, last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tenant_id BIGINT UNSIGNED NOT NULL,
    user_id BIGINT UNSIGNED NOT NULL,
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(80) NOT NULL,
    entity_id BIGINT UNSIGNED NULL,
    metadata_json JSON NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY audit_logs_tenant_created_idx (tenant_id, created_at),
    CONSTRAINT audit_logs_tenant_fk FOREIGN KEY (tenant_id) REFERENCES tenants (id) ON DELETE CASCADE,
    CONSTRAINT audit_logs_user_fk FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
