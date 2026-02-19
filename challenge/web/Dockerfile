FROM php:8.2-apache

# Install mysqli extension for MySQL connectivity
RUN docker-php-ext-install mysqli

# Write the flag from the FLAG_FILE_UPLOAD env var at container start
# Flag lives outside the web root so it can only be read via code execution
CMD ["sh", "-c", "echo \"$FLAG_FILE_UPLOAD\" > /flag.txt && chmod 644 /flag.txt && exec apache2-foreground"]
