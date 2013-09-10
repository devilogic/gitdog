/*
 * 南南密码学算法库
 * 默认算法:
 * HASH:SOBER128
 * CIPHER:AES
 * CIPHER MODE:CTR
 * SIGN:RSA
 *
 * 介绍:基于libtomcrypt算法库
 */
#if !defined(__NANAN_ALGORITHM__)
#define __NANAN_ALGORITHM__

#if defined(__cplusplus)
extern "C" {
#endif

#include "version.h"
#include "random.h"
#include "hash.h"
#include "sign.h"
#include "crypt.h"
#include "error.h"

#if !defined(APPLICATION)

	extern int nananInit();

	extern int nananHash(unsigned char* buffer, 
						 unsigned long len,
						 unsigned char* value,
						 unsigned long* value_len);

	extern int nananEncrypt(unsigned char* pt,
							unsigned long pt_len,
							unsigned char** ct,
							unsigned long* ct_len,
							char* password);


	extern int nananDecrypt(unsigned char* ct, 
							unsigned long ct_len,
							unsigned char** pt,
							unsigned long* pt_len,
							char* password);

	extern int nananMakeKey(unsigned char* public_key,
							unsigned long* public_key_size,
							unsigned char* private_key,
							unsigned long* private_key_size);

	extern int nananSign(unsigned char* buffer,
						 unsigned int len,
						 unsigned char* sigdata,
						 unsigned long* siglen,
						 unsigned char* private_key,
						 unsigned int private_key_size);

	extern int nananVerify(unsigned char* buffer,
						   unsigned int len,
						   unsigned char* sigdata,
						   unsigned long siglen,
						   unsigned char* public_key,
						   unsigned int public_key_size,
						   int* stat);


#endif

#if defined(__cplusplus)
}
#endif


#endif
