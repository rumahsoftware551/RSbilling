FROM php:8.3-fpm-alpine

RUN docker-php-ext-install pdo_mysql pcntl \
    && mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini"

COPY docker/php/entrypoint.sh /usr/local/bin/rsbilling-entrypoint
RUN chmod 0755 /usr/local/bin/rsbilling-entrypoint

WORKDIR /var/www/html
ENTRYPOINT ["rsbilling-entrypoint"]
CMD ["php-fpm", "-F"]
