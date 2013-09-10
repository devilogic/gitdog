#if !defined(__SIGN_H__)
#define __SIGN_H__
#include <tomcrypt.h>

/* 算法标识 */
#define RSA_ID			0x00
#define ECC_ID			0x01
#define DSA_ID			0x02
#define DH_ID			0x03

#define RSA_DEF_E				65537
#define	RSA_DEF_KEY_SIZE		2048
typedef struct _RSA_ALGORITHM {
	rsa_key key;					/* RSA公私钥结构 */

	long e;							/* 用户自定义的指数e */
	int key_size;					/* 用户自定义的密钥的长度 */
} RSA_ALGORITHM, *PRSA_ALGORITHM;

typedef struct _SIGN_ALGORITHM {
	int id;

	int prng_id;					/* 随机数产生器的ID */
	int hash_id;					/* 哈希算法的ID */
	int crypt_id;					/* 对称加解密算法的ID */
	
	unsigned char* public_key;		/* 导出的公钥 */
	unsigned long public_key_size;

	unsigned char* private_key;		/* 导出的私钥 */
	unsigned long private_key_size;

	unsigned char* result;          /* 签名后的结果 */
	union{
		unsigned long result_size;
		int verify_result;          /* 验证结果 */
	};

	prng_state prng;				/* 随机状态结构 */

	PRSA_ALGORITHM rsa;				/* RSA算法结构 */
} SIGN_ALGORITHM, *PSIGN_ALGORITHM;

int signInit();
int signImportKey(PSIGN_ALGORITHM sign, int type, char* key_file_path);
int signMakePK(PSIGN_ALGORITHM sign, char* key_path); 
PSIGN_ALGORITHM signAlloc(int id, int prng_id, int hash_id, int crypt_id);
void signFree(PSIGN_ALGORITHM sign);

#define SIGN_DATA_FROM_FILE       0
#define SIGN_DATA_FROM_STDIN      1
#define SIGN_DATA_FROM_BUF        2
int signSignVerify(PSIGN_ALGORITHM sign, int source, 
				   int verify, char* data, unsigned long len,
				   unsigned char* sigdata, unsigned long siglen);

void signPrintAlgorithm(int print_id);
void signPrintSign(PSIGN_ALGORITHM sign);
void signPrintKey(PSIGN_ALGORITHM sign);

#endif
