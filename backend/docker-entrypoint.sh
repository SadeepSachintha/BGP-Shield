#!/bin/sh
set -e

# Ensure SQLite database exists
if [ ! -f /var/www/database/database.sqlite ]; then
    touch /var/www/database/database.sqlite
    chmod 666 /var/www/database/database.sqlite
fi

# Ensure storage directories exist and have write permissions
mkdir -p /var/www/storage/framework/sessions \
         /var/www/storage/framework/views \
         /var/www/storage/framework/cache \
         /var/www/storage/logs \
         /var/www/bootstrap/cache
chmod -R 777 /var/www/storage /var/www/bootstrap/cache

# Generate application key if not set
if [ -z "$APP_KEY" ]; then
    php artisan key:generate --force
fi

# Run migrations
php artisan migrate --force

echo "[*] Starting Laravel Incident Gateway on 0.0.0.0:8080..."
exec php artisan serve --host=0.0.0.0 --port=8080
