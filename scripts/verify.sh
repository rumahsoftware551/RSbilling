#!/bin/sh
set -eu

find app config database public tests -name '*.php' -print0 | xargs -0 -n1 php -l
php tests/security_smoke.php
