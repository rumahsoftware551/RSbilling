#!/bin/sh
set -eu

if [ "${RSBILLING_SKIP_INSTALL:-0}" != "1" ]; then
    attempt=0
    until php /var/www/html/database/install.php; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 30 ]; then
            echo "Database tidak siap setelah 30 percobaan." >&2
            exit 1
        fi
        sleep 2
    done

    php /var/www/html/database/seed.php
fi
exec "$@"
