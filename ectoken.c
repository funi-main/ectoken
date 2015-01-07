#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/blowfish.h>
#include <string.h>

#include "php.h"
#include "php_ectoken.h"

#pragma mark ======== Preprocessor tables ========

#define n2l(c,l)        (l =((unsigned long)(*((c)++)))<<24L, \
                         l|=((unsigned long)(*((c)++)))<<16L, \
                         l|=((unsigned long)(*((c)++)))<< 8L, \
                         l|=((unsigned long)(*((c)++))))

#define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                         *((c)++)=(unsigned char)(((l)     )&0xff))

#pragma mark ======== Function Prototypes ========

static void bfencrypt(unsigned char *keydata, int keydatalen, const unsigned char *in, unsigned char *out, unsigned int inlen);
static void cfb64_encrypt(const unsigned char* in, unsigned char* out, long length, BF_KEY* schedule, unsigned char* ivec, int *num, int encrypt);
static void tohex (char *ptr, char *buf, unsigned int size);
static void prefix_token_plaintext(char * input, char * output);
static void strip_token_plaintext(char * input, char * output);

#pragma mark ======== PHP macros ========

static zend_function_entry ectoken_functions[] = {
	PHP_FE(ectoken_generate, NULL)
	{NULL, NULL, NULL}
};

#pragma mark ======== PHP macros ========

zend_module_entry ectoken_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    PHP_ECTOKEN_EXTNAME,
    ectoken_functions,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    PHP_ECTOKEN_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_ECTOKEN
ZEND_GET_MODULE(ectoken)
#endif

#pragma mark ======== PHP Functionality ========

PHP_FUNCTION(ectoken_generate){
	char *key;
	char *string;
	int key_len, string_len = 0;
	unsigned int i	= 0;


	/** Parse the incoming variables **/
#ifdef ZEND_ENGINE_2
	zval *this = getThis();
#endif
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &string, &string_len) == FAILURE) {
	        RETURN_NULL();
	}

	/** Check the length of the input string. At this time we do no support input longer than 256 characters
	as it can cause problems on the backend. **/
	if (strlen(string)+1 > 256){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Token text is longer than 256 characters.");
		RETURN_NULL();
	}

	/** encryptedstr is the final output buffer **/
	/** Allocate 1024 bytes, our theoretical max, for it and zero it out. **/
	char * encryptedstr = (char*)ecalloc(1024, sizeof(char) );
	if (encryptedstr == (char *) NULL){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Unable to allocate buffer");
		RETURN_NULL();
	}

	/** strippedstr will hold the modified string **/
	char * strippedstr = (char *)ecalloc(strlen(string) + 14, sizeof(char) );
	if (strippedstr == (char *) NULL){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Unable to allocate buffer");
		RETURN_NULL();
	}

	(void)strip_token_plaintext(string, strippedstr);

	/** plaintextstr is the buffer we will pass off to the libcrypt blowfish functions. **/
	/** Allocate it and zero out the memory. **/
	char * plaintextstr = (char *)ecalloc(strlen(strippedstr) + 15, sizeof(char) );
	if (plaintextstr == (char *) NULL){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Unable to allocate buffer");
		RETURN_NULL();
	}

	/** prepend with ec_secure=032, for example **/
	(void)prefix_token_plaintext(strippedstr, plaintextstr);

	/** encrypt the new buffer **/
    bfencrypt((unsigned char*)key, strlen(key), (unsigned char*)plaintextstr,
		(unsigned char*)encryptedstr, strlen(plaintextstr)+1);

	/** convert to hex string and write into PHP's output buffer. **/
	/** Since result is going to hold a hex string, it needs to be larger than **/
	/** the binary that's being converted to hex. **/
	char * result = (char *)ecalloc(strlen(plaintextstr) * 4 + 1, sizeof(char));
	if (result == (char *) NULL){
		php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Unable to allocate buffer");
		RETURN_NULL();
	}

	/** Convert the resulting binary string stored in encryptedstr to hexadecimal **/

	(void)tohex(encryptedstr, result, strlen(plaintextstr) );

	/** Free allocated memory. Not sure we allocated enough here. **/
	if (plaintextstr != NULL){
		efree(plaintextstr);
	}
	if (encryptedstr != NULL){
		efree(encryptedstr);
	}
	if (strippedstr != NULL){
		efree(strippedstr);
	}
	if (result != NULL){
		RETVAL_STRINGL(result, strlen(result), 1);
		efree(result);
	}
}

#pragma mark ======== Non-PHP crypto functions ========

/**
 *
 *
 * @param in
 * @param out
 * @param length
 * @param schedule
 * @param ivec
 * @param num
 * @param encrypt
 */

static void cfb64_encrypt(const unsigned char* in, unsigned char* out, long length,
   BF_KEY* schedule,
   unsigned char* ivec,
   int *num,
   int encrypt)
{
  register BF_LONG v0,v1,t;
  register int n= *num;
  register long l=length;
  BF_LONG ti[2];
  unsigned char *iv,c,cc;

  iv=(unsigned char *)ivec;
  while (l--)
  {
    if (n == 0)
    {
      n2l(iv,v0); ti[0]=v0;
      n2l(iv,v1); ti[1]=v1;
      BF_encrypt((BF_LONG*)ti,schedule);
      iv=(unsigned char *)ivec;
      t=ti[0]; l2n(t,iv);
      t=ti[1]; l2n(t,iv);
      iv=(unsigned char *)ivec;
    }
    c= *(in++)^iv[n];
    *(out++)=c;
    iv[n]=c;
    n=(n+1)&0x07;
  }
  v0=v1=ti[0]=ti[1]=t=c=cc=0;
  *num=n;
}

/**
 *
 * @param keydata
 * @param keydatalen
 * @param in
 * @param out
 * @param inlen
 */

static void bfencrypt(unsigned char *keydata, int keydatalen, const unsigned char *in, unsigned char *out, unsigned int inlen) {
  BF_KEY key;
  unsigned char ivec[32];
  int num=0;
  /** set up for encryption **/
  BF_set_key(&key, keydatalen, keydata);
  memset(ivec, '\0', 32);
  cfb64_encrypt(in, out, inlen, &key, ivec, &num, BF_ENCRYPT);
}


/**
 * Convert a binary string to it's hexadecimal representation
 * Passes splint check
 * @param ptr Binary string
 * @param buf The resulting hex string
 * @param size The size of the resulting hex string
 */

static void tohex (char *input, char *output, unsigned int input_size){
	static const char 	hex[17]	= "0123456789abcdef";
	unsigned int 		c 		= 0;
	unsigned int 		i 		= 0;

	do {
		c = (unsigned int)*input++ & 0xff;
		*output++ = (char)hex[c >> 4];
		*output++ = (char)hex[c & 15];
		i++;
	} while (i < input_size);
	*output++ = (char)0;
}

/**
 * Adds 'ecsecure=LENGTH' to a string.
 * This tells the api how much data is in the handle before encryption.
 *
 * @param input
 * @param output
 */

static void prefix_token_plaintext(char * input, char * output){
	/** prepend with ec_secure=032, for example **/
	(void)snprintf(output, strlen(input) + 15 , "ec_secure=%03d&%s", strlen(input) + 14, input);
	return;
}

/**
 * Removes the parameter 'ecsecure=1' from a string.
 * This is to preserve backwards compatibility with older versions of the API.
 *
 * @param input
 * @param output
 */

static void strip_token_plaintext(char * input, char * output){
	char* ecsecure_check_ptr = strstr(input, "ec_secure=1");
	if(ecsecure_check_ptr > 0 && ecsecure_check_ptr != NULL){
		/** ec_secure was found in the string, strip it out **/
		if(input == ecsecure_check_ptr){
			/** found at beginning, skip over and copy the rest of the string **/
			strncpy(output, (ecsecure_check_ptr += 12), strlen(input) );
		} else {
			/** it's somewhere else in the string, scrub it out **/
			/** break the string into two parts, first string null terminate where we found ec_secure **/
			*ecsecure_check_ptr = (char)0;
			(void)snprintf(output, (size_t)(ecsecure_check_ptr + 11), "%s%s", input);
			/** above we combine what was before ec_secure with what is after ec_secure's start position plus 11 octets **/
		}
	} else {
		/** there was no ec_secure found within the string, so we just copy the string **/
		strncpy(output,input, strlen(input) );
	}
	return;
}
