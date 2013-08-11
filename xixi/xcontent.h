#if !defined(__XCONTENT_H__)
#define __XCONTENT_H__

typedef struct _XCONTENT {
	unsigned int magic;
	unsigned int version;          /* 版本 */
	unsigned char checksum[16];    

	unsigned int crypt_count;      /* 有多少人对其进行加密 */
	unsigned int data_size;        /* 加密后的数据长度 */
	unsigned int sign_size;        /* owner的签名 */

	/* 加密后的数据 */
	/* XID对列，加密者靠前者，在前面 */
	/* owner的签名 */
} XCONTENT, *PXCONTENT;

#endif
