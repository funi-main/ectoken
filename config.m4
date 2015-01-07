PHP_ARG_ENABLE(ectoken, whether to enable EdgeCast Token support,
[ --enable-ectoken   Enable EdgeCast Token support])

if test "$PHP_ECTOKEN" = "yes"; then
  AC_DEFINE(HAVE_ECTOKEN, 1, [Whether you have EdgeCast Token])
  PHP_NEW_EXTENSION(ectoken, ectoken.c, $ext_shared)
  PHP_ADD_LIBRARY(crypto)
fi
