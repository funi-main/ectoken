#ifndef PHP_ECTOKEN_H
#define PHP_ECTOKEN_H 1

#define PHP_ECTOKEN_VERSION "1.1"
#define PHP_ECTOKEN_EXTNAME "ectoken"

PHP_FUNCTION(ectoken_generate);

extern zend_module_entry ectoken_module_entry;
#define phpext_ectoken_ptr &ectoken_module_entry

#endif
