
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <strings.h>

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "ext/standard/base64.h"
#include "ext/standard/php_array.h"
#include "ext/json/php_json.h"
#include "php_jwt.h"

/* If you declare any globals in php_jwt.h uncomment this:
ZEND_DECLARE_MODULE_GLOBALS(jwt)
*/

/* True global resources - no need for thread safety here */
static int le_jwt;

static unsigned char *php_jwt_urlsafe_base64_encode(const unsigned char *str, int len)
{
	unsigned char *result;
	int result_len;

	// base64 encode
	result = php_base64_encode(str, len, &result_len);

	// conver it as url safe.
	int i, t;
	for (i = t = 0; i < result_len; i++) {
		switch (result[i]) {
		case '+':
			result[t] = '-';
			break;
		case '/':
			result[t] = '_';
			break;
		case '=':
			continue;
		}

		t++;
	}

	result[t] = '\0';

	return result;
}

static unsigned char *php_jwt_part_encode(zval *val)
{
	int options = 0;
	smart_str json_str = {0};
	unsigned char *result;

	// TODO: How do I handle JSON error?
	php_json_encode(&json_str, val, options TSRMLS_CC);

	// url safe base64 encode
	result = php_jwt_urlsafe_base64_encode((unsigned char*)json_str.c, json_str.len);
	smart_str_free(&json_str);

	return result;
}

static int php_jwt_hmac_sha256(const void *key, int key_len,
                           const unsigned char *data, int data_len,
                           unsigned char *result, unsigned int *result_len)
{
    HMAC(EVP_sha256(), key, key_len, data, data_len, result, result_len);
	return 0;
}

static unsigned char *php_jwt_urlsafe_base64_decode(unsigned char *str, int len, int *result_len)
{
	unsigned char *result;
	int i, z;
	smart_str sstr = {0};
	smart_str_appendl(&sstr, str, len);

	for (i = 0; i < len; i++) {
		switch (sstr.c[i]) {
		case '-':
			sstr.c[i] = '+';
			break;
		case '_':
			sstr.c[i] = '/';
			break;
		}
	}

	z = 4 - (len % 4);
	if (z < 4) {
		while (z--)
			sstr.c[i++] = '=';
	}

	result = php_base64_decode((unsigned char *)sstr.c, sstr.len, result_len);

	smart_str_free(&sstr);

	return result;
}

static int php_jwt_part_decode(unsigned char *base64_str, int base64_str_len, zend_bool assoc, zval *return_value)
{
	char *json_str;
	int json_str_len;

	json_str = (char *)php_jwt_urlsafe_base64_decode(base64_str, base64_str_len, &json_str_len);

	if (json_str == NULL) {
		return FAILURE;
	}

	php_json_decode(return_value, json_str, json_str_len, assoc, 512 TSRMLS_CC);
	efree(json_str);

	if (Z_TYPE_P(return_value) == IS_NULL) {
		return FAILURE;
	}

	return SUCCESS;
}


PHP_FUNCTION(jwt_encode)
{
	zval *payload;
	char *key;
	int key_len;
	char *alg = "HS256";
	int alg_len = 5;
	zval *option_header = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zs|sa", &payload, &key, &key_len, &alg, &alg_len, &option_header) == FAILURE) {
		return;
	}

	// generated JWT token.
	smart_str result = {0};

	// header
	char *header_base64;

	// header as zval.
	zval *header;
	ALLOC_INIT_ZVAL(header);
	array_init(header);
	// default values
	add_assoc_stringl(header, "alg", alg, alg_len, 1);
	add_assoc_string(header, "typ", "JWT", 1);

	// merge option_header param.
	if (option_header != NULL) {
		php_array_merge(Z_ARRVAL_P(header), Z_ARRVAL_P(option_header), 0 TSRMLS_CC);
	}
	header_base64 = (char *)php_jwt_part_encode(header);

	// paload
	char *payload_base64;
	payload_base64 = (char *)php_jwt_part_encode(payload);

	// concatenate header and payload
	smart_str_appendl(&result, header_base64, strlen(header_base64));
	smart_str_appendl(&result, ".", 1);
	smart_str_appendl(&result, payload_base64, strlen(payload_base64));

	efree(header_base64);
	efree(payload_base64);

	// signature
	if (strcasecmp(alg, "none") == 0) {
		// alg none.
		smart_str_appendl(&result, ".", 1);
		ZVAL_STRINGL(return_value, result.c, result.len, 1);
		smart_str_free(&result);
	} else if (strcasecmp(alg, "HS256") == 0) {
		// alg HS256.
		char *signature_base64;
		unsigned char signature[EVP_MAX_MD_SIZE];
		unsigned int signature_len;

		// sign
		HMAC(EVP_sha256(), key, key_len, (const unsigned char *)result.c, result.len, signature, &signature_len);
		signature_base64 = (char *)php_jwt_urlsafe_base64_encode(signature, signature_len);

		// append signature
		smart_str_appendl(&result, ".", 1);
		if (signature_base64 != NULL) {
			smart_str_appendl(&result, signature_base64, strlen(signature_base64));
		}

		efree(signature_base64);

		ZVAL_STRINGL(return_value, result.c, result.len, 1);

		smart_str_free(&result);
	} else if (strcasecmp(alg, "HS384") == 0) {
		// alg HS384.
		char *signature_base64;
		unsigned char signature[EVP_MAX_MD_SIZE];
		unsigned int signature_len;

		// sign
		HMAC(EVP_sha384(), key, key_len, (const unsigned char *)result.c, result.len, signature, &signature_len);
		signature_base64 = (char *)php_jwt_urlsafe_base64_encode(signature, signature_len);

		// append signature
		smart_str_appendl(&result, ".", 1);
		if (signature_base64 != NULL) {
			smart_str_appendl(&result, signature_base64, strlen(signature_base64));
		}

		efree(signature_base64);

		ZVAL_STRINGL(return_value, result.c, result.len, 1);

		smart_str_free(&result);
	} else if (strcasecmp(alg, "HS512") == 0) {
		// alg HS512.
		char *signature_base64;
		unsigned char signature[EVP_MAX_MD_SIZE];
		unsigned int signature_len;

		// sign
		HMAC(EVP_sha512(), key, key_len, (const unsigned char *)result.c, result.len, signature, &signature_len);
		signature_base64 = (char *)php_jwt_urlsafe_base64_encode(signature, signature_len);

		// append signature
		smart_str_appendl(&result, ".", 1);
		if (signature_base64 != NULL) {
			smart_str_appendl(&result, signature_base64, strlen(signature_base64));
		}

		efree(signature_base64);

		ZVAL_STRINGL(return_value, result.c, result.len, 1);

		smart_str_free(&result);
	} else {
		// unsupported algorithm.
		ZVAL_FALSE(return_value);
		smart_str_free(&result);

		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Unsupported algorithm");
		return;
	}
}

PHP_FUNCTION(jwt_decode)
{
	char *token;
	int token_len;
	/* key: accept string or array, now supports only string*/
	zval *key;
	zend_bool assoc = 0;
	zval *allowed_algs = NULL;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sz|ba", &token, &token_len, &key, &assoc, &allowed_algs) == FAILURE) {
		return;
	}
	if (allowed_algs == NULL) {
		// it is not passed alg as a argument. set default value.
		// default algorithm is "HS256"
		ALLOC_INIT_ZVAL(allowed_algs);
		array_init(allowed_algs);
		add_next_index_string(allowed_algs, "HS256", 1);
	}

	char *header_base64;
	int header_base64_len;

	char *payload_base64;
	int payload_base64_len;

	char *header_and_payload_base64;
	int header_and_payload_base64_len;

	char *signature_base64;
	int signature_base64_len;

	char *delim_p;

	// get header
	delim_p = (char *)memchr(token, '.', token_len);
	if (delim_p == NULL) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Wrong number of segments");
		return;
	}
	header_base64 = token;
	header_base64_len = delim_p - header_base64;

	// check remaining characters length
	if (token_len - header_base64_len - 1 <= 0) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Wrong number of segments");
		return;
	}

	// get paylaod
	payload_base64 = delim_p + 1;
	delim_p = (char *)memchr(payload_base64, '.', token_len - header_base64_len - 1);
	if (delim_p == NULL) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Wrong number of segments");
		return;
	}
	payload_base64_len = delim_p - payload_base64;

	header_and_payload_base64 = token;
	header_and_payload_base64_len = header_base64_len + payload_base64_len + 1;

	// check remaining characters length
	if (token_len - header_base64_len - payload_base64_len - 2 <= 0) {
		// not found signature. but if alg is 'none', it is valid token.
		signature_base64_len = 0;
	} else {
		// get paylaod
		signature_base64 = delim_p + 1;
		signature_base64_len = token_len - header_base64_len - payload_base64_len - 2;
	}

	// // for debugging...
	// PHPWRITE(header_base64, header_base64_len);
	// php_printf("\n");
	// PHPWRITE(payload_base64, payload_base64_len);
	// php_printf("\n");
	// PHPWRITE(header_and_payload_base64, header_and_payload_base64_len);
	// php_printf("\n");
	// PHPWRITE(signature_base64, signature_base64_len);
	// php_printf("\n");
	// php_printf("signature_base64_len = %d\n", signature_base64_len);
	// php_printf("\n");


	zval *header_z;
	ALLOC_INIT_ZVAL(header_z);
	if (php_jwt_part_decode((unsigned char *)header_base64, header_base64_len, 1, header_z) == FAILURE) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid header encoding");
		return;
	}

	zval *payload_z;
	ALLOC_INIT_ZVAL(payload_z);

	if (php_jwt_part_decode((unsigned char *)payload_base64, payload_base64_len, assoc, payload_z) == FAILURE) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Invalid claims encoding");
		return;
	}

	HashTable *header_hash = Z_ARRVAL_P(header_z);
	zval **header_alg_z;
	if (zend_hash_find(header_hash, "alg", sizeof("alg"), (void **)&header_alg_z) == FAILURE) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Empty algorithm");
		return;
	}

	// // for debugging...
	// php_printf("alg = ");
	// PHPWRITE(Z_STRVAL_PP(header_alg_z), Z_STRLEN_PP(header_alg_z));
	// php_printf("\n");

	char *alg = Z_STRVAL_PP(header_alg_z);
	int alg_len = Z_STRLEN_PP(header_alg_z);

	if (strcasecmp(alg, "none") != 0
		&& strcasecmp(alg, "HS256") != 0
		&& strcasecmp(alg, "HS384") != 0
		&& strcasecmp(alg, "HS512") != 0) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Algorithm not supported");
		return;
	}

	// Is it allowed alg?
	int alg_ok = 0;
	HashTable *allowed_algs_arr = Z_ARRVAL_P(allowed_algs);
    HashPosition pos;
	zval **data;
	for(zend_hash_internal_pointer_reset_ex(allowed_algs_arr, &pos);
		zend_hash_get_current_data_ex(allowed_algs_arr, (void**) &data, &pos) == SUCCESS;
		zend_hash_move_forward_ex(allowed_algs_arr, &pos)) {

		if (Z_TYPE_PP(data) == IS_STRING) {
			if (strcasecmp(alg, Z_STRVAL_PP(data)) == 0) {
				alg_ok = 1;
				break;
			}
		}
	}

	if (alg_ok == 0) {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Algorithm not allowed");
		return;
	}

	char *signature;
	int signature_len;
	signature = (char *)php_jwt_urlsafe_base64_decode((unsigned char *)signature_base64, signature_base64_len, &signature_len);

	// verify
	if (strcasecmp(alg, "none") == 0) {
		// alg none.
	} else if (strcasecmp(alg, "HS256") == 0) {
		char *hash_signature_base64;
		unsigned char hash_signature[EVP_MAX_MD_SIZE];
		unsigned int hash_signature_len;

		// sign
		HMAC(EVP_sha256(), Z_STRVAL_P(key), Z_STRLEN_P(key), (const unsigned char *)header_and_payload_base64, header_and_payload_base64_len, hash_signature, &hash_signature_len);

		// verify
		if (signature_len != hash_signature_len) {
			ZVAL_FALSE(return_value);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Signature verification failed");
			return;
		}

		if (memcmp(signature, hash_signature, hash_signature_len) != 0) {
			ZVAL_FALSE(return_value);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Signature verification failed");
			return;
		}
	} else if (strcasecmp(alg, "HS384") == 0) {
		char *hash_signature_base64;
		unsigned char hash_signature[EVP_MAX_MD_SIZE];
		unsigned int hash_signature_len;

		// sign
		HMAC(EVP_sha384(), Z_STRVAL_P(key), Z_STRLEN_P(key), (const unsigned char *)header_and_payload_base64, header_and_payload_base64_len, hash_signature, &hash_signature_len);

		// verify
		if (signature_len != hash_signature_len) {
			ZVAL_FALSE(return_value);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Signature verification failed");
			return;
		}

		if (memcmp(signature, hash_signature, hash_signature_len) != 0) {
			ZVAL_FALSE(return_value);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Signature verification failed");
			return;
		}
	} else if (strcasecmp(alg, "HS512") == 0) {
		char *hash_signature_base64;
		unsigned char hash_signature[EVP_MAX_MD_SIZE];
		unsigned int hash_signature_len;

		// sign
		HMAC(EVP_sha512(), Z_STRVAL_P(key), Z_STRLEN_P(key), (const unsigned char *)header_and_payload_base64, header_and_payload_base64_len, hash_signature, &hash_signature_len);

		// verify
		if (signature_len != hash_signature_len) {
			ZVAL_FALSE(return_value);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Signature verification failed");
			return;
		}

		if (memcmp(signature, hash_signature, hash_signature_len) != 0) {
			ZVAL_FALSE(return_value);
			php_error_docref(NULL TSRMLS_CC, E_WARNING, "Signature verification failed");
			return;
		}
	} else {
		ZVAL_FALSE(return_value);
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Algorithm not supported");
		return;
	}

	//HashTable *header_hash = zend_std_get_properties(header_z TSRMLS_CC);
	RETURN_ZVAL(payload_z, 1, 0);
}

/* {{{ php_jwt_init_globals
 */
/* Uncomment this function if you have INI entries
static void php_jwt_init_globals(zend_jwt_globals *jwt_globals)
{
	jwt_globals->global_value = 0;
	jwt_globals->global_string = NULL;
}
*/
/* }}} */

/* {{{ PHP_MINIT_FUNCTION
 */
PHP_MINIT_FUNCTION(jwt)
{
	/* If you have INI entries, uncomment these lines
	REGISTER_INI_ENTRIES();
	*/

#ifdef PHP_SESSION
    php_session_register_module(&ps_mod_jwt);
#endif

	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MSHUTDOWN_FUNCTION
 */
PHP_MSHUTDOWN_FUNCTION(jwt)
{
	/* uncomment this line if you have INI entries
	UNREGISTER_INI_ENTRIES();
	*/
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request start */
/* {{{ PHP_RINIT_FUNCTION
 */
PHP_RINIT_FUNCTION(jwt)
{
	return SUCCESS;
}
/* }}} */

/* Remove if there's nothing to do at request end */
/* {{{ PHP_RSHUTDOWN_FUNCTION
 */
PHP_RSHUTDOWN_FUNCTION(jwt)
{
	return SUCCESS;
}
/* }}} */

/* {{{ PHP_MINFO_FUNCTION
 */
PHP_MINFO_FUNCTION(jwt)
{
	php_info_print_table_start();
	// php_info_print_table_header(2, "jwt support", "enabled");
	php_info_print_table_row(2, "jwt support", "enabled" );
	php_info_print_table_end();

	/* Remove comments if you have entries in php.ini
	DISPLAY_INI_ENTRIES();
	*/
}
/* }}} */

/* {{{ jwt_functions[]
 *
 * Every user visible function must have an entry in jwt_functions[].
 */
const zend_function_entry jwt_functions[] = {
	PHP_FE(jwt_encode,	NULL)
	PHP_FE(jwt_decode,	NULL)
	PHP_FE_END
};
/* }}} */

/* {{{ jwt_module_entry
 */
zend_module_entry jwt_module_entry = {
	STANDARD_MODULE_HEADER,
	"jwt",
	jwt_functions,
	PHP_MINIT(jwt),
	PHP_MSHUTDOWN(jwt),
	PHP_RINIT(jwt),
	PHP_RSHUTDOWN(jwt),
	PHP_MINFO(jwt),
	PHP_JWT_VERSION,
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_JWT
ZEND_GET_MODULE(jwt)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
