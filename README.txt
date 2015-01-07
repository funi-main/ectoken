EdgeCast Token Authentication extension for PHP
===============================================

Files included in this release:
config.m4
ectoken.c
Makefile.in
php_ectoken.h
README.txt
example.php

===============================================
To build:
phpize
./configure --enable-ectoken
make

===============================================
To deploy:
Copy modules/ectoken.so into your PHP extensions directory.
Enable the extension in php.ini:

extension=ectoken.so

Restart your HTTP server
===============================================

Usage:

PHP:
ectoken_generate($key, $string);

Follow the instructions in the EdgeCast Token Authentication 1.4 guide. Pass the above function your key as the first parameter ($key), and all of your token authentication parameters as the second ($string). ectoken_generate will return your token as a string. On error this function will return null, and in most cases output the error to your php ERROR_LOG. Please note that in this release the maximum length of $string is 256 characters.

Example:
<?php
$key = "12345678";

$params = "ec_secure=1&ec_expire=1185943200&ec_ip=111.11.111.11&ec_country_allow=US&ec_ 
ref_allow=ec1.com";

$token = ectoken_generate($key, $params);
echo $token;

?>