# Multi-stage build for Laravel Backend
FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --prefer-dist --optimize-autoloader --ignore-platform-reqs

FROM php:8.2-cli-alpine

WORKDIR /var/www

# Install runtime system packages and PHP extensions
RUN apk add --no-cache \
    sqlite-libs \
    sqlite-dev \
    libzip-dev \
    curl \
    && docker-php-ext-install pdo pdo_sqlite pcntl bcmath \
    && rm -rf /var/cache/apk/*

# Copy composer dependencies from vendor stage
COPY --from=vendor /app/vendor /var/www/vendor

# Copy application files
COPY . /var/www

# Make entrypoint executable
RUN chmod +x /var/www/docker-entrypoint.sh

# Expose port 8080
EXPOSE 8080

ENTRYPOINT ["/var/www/docker-entrypoint.sh"]
