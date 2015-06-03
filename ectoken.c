#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <openssl/blowfish.h>
#include <string.h>

#include "php.h"
#include "php_ectoken.h"
#include "ectoken_v3.h"

#pragma mark ======== Preprocessor tables ========

/*******************************************************************************
 * constants
 *******************************************************************************/
// Set limit to 512
#define kMAX_TOKEN_LENGTH 512

/***********************************************************
 * Max length to support extra random sentinels is
 * example -using min=4 max=8 and query parameter is "r"
 *   &r=rand_str[4-8]...&r=rand_str[4-8]
 *   2x("&r=") + 2x8 (max random str size)
 *   6 + 16 == 22
 ***********************************************************/
#define kRAND_QUERY_STR "r"
#define kRAND_QUERY_SIZE (sizeof(kRAND_QUERY_STR) + 1)
#define kRAND_STR_SIZE_MIN 4
#define kRAND_STR_SIZE_MAX 8
#define kMAX_TOKEN_RAND_LENGTH (kMAX_TOKEN_LENGTH - ((2*kRAND_QUERY_SIZE)+(2*kRAND_STR_SIZE_MAX)))

/*******************************************************************************
 * macros
 *******************************************************************************/
#define n2l(c,l) (l =((unsigned long)(*((c)++)))<<24L, \
                  l|=((unsigned long)(*((c)++)))<<16L, \
                  l|=((unsigned long)(*((c)++)))<< 8L, \
                  l|=((unsigned long)(*((c)++))))

#define l2n(l,c) (*((c)++)=(unsigned char)(((l)>>24L)&0xff), \
                  *((c)++)=(unsigned char)(((l)>>16L)&0xff), \
                  *((c)++)=(unsigned char)(((l)>> 8L)&0xff), \
                  *((c)++)=(unsigned char)(((l)     )&0xff))

#pragma mark ======== Function Prototypes ========

static void bfencrypt(unsigned char *keydata, int keydatalen, const unsigned char *in, unsigned char *out, unsigned int inlen);
static void tohex (char *ptr, char *buf, unsigned int size);
static void prefix_token_plaintext(char * input, char * output);
static void strip_token_plaintext(char * input, char * output);
static void gen_random_str(char *ao_s);

#pragma mark ======== PHP macros ========

static zend_function_entry ectoken_functions[] = {
    PHP_FE(ectoken_init, NULL)
    PHP_FE(ectoken_encrypt_token, NULL)
    PHP_FE(ectoken_decrypt_token, NULL)
    PHP_FE(ectoken_generate, NULL)
    {NULL, NULL, NULL}
};

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

PHP_FUNCTION(ectoken_init)
{
        if (ectoken_init())
        {
                RETURN_FALSE;
        }
        RETURN_TRUE;
}

PHP_FUNCTION(ectoken_decrypt_token)
{
        char *key;
        char *token;
        int key_len, token_len = 0;
        /** Parse the incoming variables **/
#ifdef ZEND_ENGINE_2
        zval *this = getThis();
#endif
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key,
                                  &key_len, &token, &token_len) == FAILURE)
        {
                RETURN_NULL();
        }

        int plaintext_length = ectoken_decrypt_required_size(token_len);
        char* plaintext = emalloc(sizeof(char)*plaintext_length);

        int ret = ectoken_decrypt_token(plaintext, &plaintext_length,
                                        token, token_len,
                                        key, key_len);
        if (ret < 0)
        {
                efree(plaintext);
                RETURN_NULL();
        }
        RETVAL_STRINGL(plaintext, plaintext_length, 0);

}

PHP_FUNCTION(ectoken_encrypt_token)
{
        char *key;
        char *query_string;
        int key_len, query_string_len = 0;
        /** Parse the incoming variables **/
#ifdef ZEND_ENGINE_2
        zval *this = getThis();
#endif
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key,
                                  &key_len, &query_string,
                                  &query_string_len) == FAILURE)
        {
                RETURN_NULL();
        }

        int ciphertext_length = ectoken_encrypt_required_size(query_string_len);
        char* ciphertext = emalloc(sizeof(char)*ciphertext_length);

        int ret = ectoken_encrypt_token(ciphertext, &ciphertext_length,
                                        query_string, query_string_len,
                                        key, key_len);

        if (ret < 0)
        {
                efree(ciphertext);
                RETURN_NULL();
        }
        RETVAL_STRINGL(ciphertext, ciphertext_length, 0);
}

PHP_FUNCTION(ectoken_generate){
        char *key;
        char *string;
        int key_len, string_len = 0;
        unsigned int i  = 0;


        /** Parse the incoming variables **/
#ifdef ZEND_ENGINE_2
        zval *this = getThis();
#endif
        if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &key, &key_len, &string, &string_len) == FAILURE) {
                RETURN_NULL();
        }

        /** Check the length of the input string. At this time we do no support input longer than 512 characters
        as it can cause problems on the backend. **/
        if (strlen(string)+1 > 512){
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Token text is longer than 512 characters.");
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

        /** add optional random sentinels **/
        int add_rand_sentinels_flag = (strlen(strippedstr)+1 < kMAX_TOKEN_RAND_LENGTH);
        if (add_rand_sentinels_flag)
        {
                unsigned int ec_secure_str_len = strlen(strippedstr) + 15 + (2*kRAND_QUERY_SIZE + 2*kRAND_STR_SIZE_MAX);
                char * ec_secure_str = (char *)ecalloc(ec_secure_str_len, sizeof(char) );
                if (ec_secure_str == (char *) NULL){
                        php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Unable to allocate buffer");
                        RETURN_NULL();
                }

                // Generate random strings
                char r1[9] = "";
                char r2[9] = "";
                gen_random_str(r1);
                gen_random_str(r2);
                snprintf(ec_secure_str, ec_secure_str_len, "%s=%s&%s&ec_secure=%03d&%s=%s",
                                kRAND_QUERY_STR,
                                r1,
                                strippedstr,
                                (int)(strlen(strippedstr)+14 + (2*kRAND_QUERY_SIZE + strlen(r1) + strlen(r2))),
                                kRAND_QUERY_STR,
                                r2);
                if (strippedstr != NULL){
                        efree(strippedstr);
                }
                strippedstr = ec_secure_str;
        }
        else
        {
                unsigned int ec_secure_str_len = strlen(strippedstr) + 15;
                char * ec_secure_str = (char *)ecalloc(ec_secure_str_len, sizeof(char) );
                if (ec_secure_str == (char *) NULL){
                        php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Unable to allocate buffer");
                        RETURN_NULL();
                }
                snprintf(ec_secure_str, ec_secure_str_len, "%s&ec_secure=%03d",
                                strippedstr,
                                (int)(strlen(strippedstr)+14));
                if (strippedstr != NULL){
                        efree(strippedstr);
                }
                strippedstr = ec_secure_str;
        }

        /** encrypt the new buffer **/
        bfencrypt((unsigned char*)key, strlen(key), (unsigned char*)strippedstr,
                  (unsigned char*)encryptedstr, strlen(strippedstr)+1);

        /** convert to hex string and write into PHP's output buffer. **/
        /** Since result is going to hold a hex string, it needs to be larger than **/
        /** the binary that's being converted to hex. **/
        char * result = (char *)ecalloc(strlen(strippedstr) * 4 + 1, sizeof(char));
        if (result == (char *) NULL){
                php_error_docref(NULL TSRMLS_CC, E_ERROR, "ectoken: Unable to allocate buffer");
                RETURN_NULL();
        }

        /** Convert the resulting binary string stored in encryptedstr to hexadecimal **/

        (void)tohex(encryptedstr, result, strlen(strippedstr) );

        /** Free allocated memory. Not sure we allocated enough here. **/
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
  BF_cfb64_encrypt(in, out, inlen, &key, ivec, &num, BF_ENCRYPT);
}


/**
 * Convert a binary string to it's hexadecimal representation
 * Passes splint check
 * @param ptr Binary string
 * @param buf The resulting hex string
 * @param size The size of the resulting hex string
 */

static void tohex (char *input, char *output, unsigned int input_size){
        static const char       hex[17] = "0123456789abcdef";
        unsigned int            c               = 0;
        unsigned int            i               = 0;

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
        /** append with ec_secure=032, for example **/
        (void)snprintf(output, strlen(input) + 15 , "%s&ec_secure=%03d", input, strlen(input) + 14);
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
        if(ecsecure_check_ptr > 0){
                /** ec_secure was found in the string, strip it out **/
                if(input == ecsecure_check_ptr){
                        /** found at beginning, skip over and copy the rest of the string **/
                        strncpy(output, (ecsecure_check_ptr += 12), strlen(input) );
                } else {
                        /** it's somewhere else in the string, scrub it out **/
                        /** break the string into two parts, first string null terminate where we found ec_secure **/
                        size_t input_length = strlen(input);
                        *ecsecure_check_ptr = (char)0;
                        (void)snprintf(output, input_length, "%s%s", input, ecsecure_check_ptr + 11);
                        /** above we combine what was before ec_secure with what is after ec_secure's start position plus 11 octets **/
                }
        } else {
                /** there was no ec_secure found within the string, so we just copy the string **/
                strncpy(output,input, strlen(input) );
        }
        return;
}

/**
 * Generates random length random alphanumeric string
 *
 * @param ao_s
 */
static void gen_random_str(char *ao_s)
{
        static const char s_alphanum[] =
                "0123456789"
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz";

        /* Seed the random number generator */
        static int s_rand_seeded = 0;
        if(!s_rand_seeded)
        {
                srand(time(NULL));
                s_rand_seeded = 1;
        }

        /* Get random length between min-max */
        int l_len = (rand() % (kRAND_STR_SIZE_MAX - kRAND_STR_SIZE_MIN + 1)) + (kRAND_STR_SIZE_MAX - kRAND_STR_SIZE_MIN);
        int i_char = 0;
        for (i_char = 0; i_char < l_len; ++i_char) {
                ao_s[i_char] = s_alphanum[rand() % (sizeof(s_alphanum) - 1)];
        }

        ao_s[l_len] = 0;
}
