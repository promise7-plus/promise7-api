FROM php:8.2-apache

# Cài đặt thư viện PDO PostgreSQL
RUN apt-get update && apt-get install -y libpq-dev \
    && docker-php-ext-install pdo pdo_pgsql

# Bật mod_rewrite cho Apache
RUN a2enmod rewrite

# Sao chép code vào thư mục web
COPY . /var/www/html/

EXPOSE 80