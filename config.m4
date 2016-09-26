PHP_ARG_ENABLE(jwt, whether to enable jwt support,
Make sure that the comment is aligned:
[  --enable-jwt           Enable jwt support])

if test "$PHP_JWT" != "no"; then
  PHP_NEW_EXTENSION(jwt, jwt.c, $ext_shared)
  PHP_SUBST(JWT_SHARED_LIBADD)
fi
