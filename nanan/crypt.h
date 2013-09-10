#if !defined(__CRYPT_H__)
#define __CRYPT_H__
#include <tomcrypt.h>

typedef enum _CRYPT_MODE {
#if defined(LTC_ECB_MODE)
	ECB_MODE = 0,
#endif

#if defined(LTC_CBC_MODE)
	CBC_MODE,
#endif

#if defined(LTC_CFB_MODE)
	CFB_MODE,
#endif

#if defined(LTC_CTR_MODE)
	CTR_MODE,
#endif

#if defined(LTC_F8_MODE)
	F8_MODE,
#endif

#if defined(LTC_LRW_MODE)
	LRW_MODE,
#endif

#if defined(LTC_OFB_MODE)
	OFB_MODE,
#endif

#if defined(LTC_XTS_MODE)
	XTS_MODE,
#endif
	MAX_CRYPT_MODE
} CRYPT_MODE, *PCRYPT_MODE;

typedef struct _CRYPT_ALGORITHM {
	int id;									/* 算法标识 */
	int hash_id;							/* hash算法标识 */
	int prng_id;                            /* 随机发生器标识 */

	CRYPT_MODE mode;                        /* 加密模式 */

	unsigned char key[MAXBLOCKSIZE];		/* 已经经过哈希的密钥 */
	int key_size;							/* 密钥的哈希值长度 */

	unsigned long blocklen;                 /* 加密算法块大小 */

	union {
#if defined(LTC_XTS_MODE)
		unsigned char xts_tweak_key[MAXBLOCKSIZE];    /* XTS模式的第二个KEY */
#endif
		unsigned char iv[MAXBLOCKSIZE];			/* IV值 */
		unsigned char iv_data[MAXBLOCKSIZE];
	};

	union {
#if defined(LTC_XTS_MODE)
		unsigned long xts_tweak_size;           /* 固定16个字节 */
#endif
		unsigned long iv_size;					/* IV的长度 */
		unsigned long iv_data_size;
	};

	unsigned int result_size;				/* 结果的大小 */
	unsigned char* result;					/* 结果 */

	/* 各种模式的KEY */
	union {
#if defined(LTC_ECB_MODE)
		symmetric_ECB ecb_key;
#endif

#if defined(LTC_CBC_MODE)
		symmetric_CBC cbc_key;
#endif

#if defined(LTC_CFB_MODE)
		symmetric_CFB cfb_key;
#endif

#if defined(LTC_CTR_MODE)
		symmetric_CTR ctr_key;
#endif

#if defined(LTC_F8_MODE)
		symmetric_F8 f8_key;
#endif

#if defined(LTC_LRW_MODE)
		symmetric_LRW lrw_key;
#endif

#if defined(LTC_OFB_MODE)
		symmetric_OFB ofb_key;
#endif

#if defined(LTC_XTS_MODE)
		symmetric_xts xts_key;
#endif
	};

	/* 一些额外的数据 */
#if defined(LTC_LRW_MODE) || defined(LTC_XTS_MODE)
	unsigned char tweak[16];               /* LRW XTS MODE使用 */
#endif

#if defined(LTC_F8_MODE)
	unsigned char salt_key[16];
	unsigned long skeylen;
#endif
	unsigned long padding_size;            /* 填充物大小 */
	unsigned char padding_data[64];        /* 填充物 */
	int after_encrypted;                   /* 表明刚刚进行完加密 */
} CRYPT_ALGORITHM, *PCRYPT_ALGORITHM;

int cryptInit();
PCRYPT_ALGORITHM cryptAlloc(int id, int mode, int hash_id, 
							int prng_id, char* key_string);
void cryptFree(PCRYPT_ALGORITHM crypt); 
int cryptRun(PCRYPT_ALGORITHM crypt, int from_stdin, int encrypt, char* files);
int cryptRun2(PCRYPT_ALGORITHM crypt, int encrypt, unsigned char* buffer, unsigned long size);
void cryptPrintAlgorithm(int print_id);
void cryptPrintResult(PCRYPT_ALGORITHM crypt, int text);
void cryptPrintMode(int print_id);

#endif
