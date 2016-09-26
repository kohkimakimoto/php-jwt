
#ifndef PHP_JWT_H
#define PHP_JWT_H

extern zend_module_entry jwt_module_entry;
#define phpext_jwt_ptr &jwt_module_entry

#define PHP_JWT_VERSION "0.1.0" /* Replace with version number for your extension */

#ifdef PHP_WIN32
#	define PHP_JWT_API __declspec(dllexport)
#elif defined(__GNUC__) && __GNUC__ >= 4
#	define PHP_JWT_API __attribute__ ((visibility("default")))
#else
#	define PHP_JWT_API
#endif

#ifdef ZTS
#include "TSRM.h"
#endif

/*
  	Declare any global variables you may need between the BEGIN
	and END macros here:

ZEND_BEGIN_MODULE_GLOBALS(jwt)
	long  global_value;
	char *global_string;
ZEND_END_MODULE_GLOBALS(jwt)
*/

/* In every utility function you add that needs to use variables
   in php_jwt_globals, call TSRMLS_FETCH(); after declaring other
   variables used by that function, or better yet, pass in TSRMLS_CC
   after the last function argument and declare your utility function
   with TSRMLS_DC after the last declared argument.  Always refer to
   the globals in your function as JWT_G(variable).  You are
   encouraged to rename these macros something shorter, see
   examples in any other php module directory.
*/

#ifdef ZTS
#define JWT_G(v) TSRMG(jwt_globals_id, zend_jwt_globals *, v)
#else
#define JWT_G(v) (jwt_globals.v)
#endif

#endif	/* PHP_JWT_H */
