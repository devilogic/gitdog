#if !defined(__PKF_H__)
#define __PKF_H__

#include <uuid/uuid.h>

#define PKF_MAGIC                                        0x1983
#define PKF_VERSION                                      0x0001

#define PKF_HEADER                                        0x00
#define PKF_PROP_PUBLIC                                   0x01
#define PKF_PROP_PRIVATE                                  0x02
#define PKF_PROP_DECRYPT_PRIVATE                          0x04
#define PKF_PROP_SIGN                                     0x08
#define PKF_PROP_ROOT                                     0x1000      /* 无任何颁发者 */

#define pkf_has_public(p) (p->property & PKF_PROP_PUBLIC != 0)
#define pkf_has_private(p) (p->property & PKF_PROP_PRIVATE != 0)
#define pkf_has_decrypt_private(p) (p->property & PKF_PROP_DECRYPT_PRIVATE != 0)
#define pkf_signed(p) (p->property & PKF_PROP_SIGN != 0)
#define pkf_is_root(p) (p->property & PKF_PROP_ROOT != 0)

/* 颁发者的签名信息 */
typedef struct _PKF_ISSUER {
	XID pkf_id;
	char name[128];
	unsigned int sign_size;
} PKF_ISSUER, *PPKF_ISSUER;

//#define PKF_VERSION_1
#if defined(PKF_VERSION_1)
/* 只记录了与签名与加密有关的信息 */
typedef struct _PKF_V1 {
	unsigned int magic;
	unsigned int version;
	unsigned int file_size;                      /* 证书大小 */
	PKF_ISSUER issuer;                           /* 颁发者 */
	char email[128];
	char organization[128];

	unsigned char checksum[20];                  /* sha1 */

	/* 证书的属性 */
	union {
		unsigned int property;                       /* 此值位置不能变动 */
		unsigned int checksum_start;
		unsigned int sign_start;
	};

	/* 证书信息 */
	XID pkf_id;                                   /* 证书的唯一ID */

	/* 加密私钥所需的密码HASH值 */
	union {
		char password[32];
		unsigned char password_hash[20];
	};

	/* 时间相关 */
	unsigned long begin_time;                       /* 颁发的时间 */
	unsigned long end_time;                         /* 失效的时间 */
	
	/* 与签名运算有关系的数据 */
	struct {
		int hash_id;
		int sign_id;
		int prng_id;
	} sign_support;

	unsigned int public_key_size;
	union {
		int crypt_id;    /* 只在使用 */
		unsigned int private_key_size;
	};

	/* 私钥导出结构 */
	/* 私钥 */
	/* 公钥 */
	/* 颁发者的签名 */
} PKF_V1, *PPKF_V1;

typedef PKF_V1 PKF, *PPKF;

#else

typedef struct _PKF {
	int a;
} PKF, *PPKF;

#endif

/* 导出私钥时使用 */
typedef struct _PKF_PRIVATE_KEY_SECURITY {
	int crypt_id;
} PKF_PRIVATE_KEY_SECURITY, *PPKF_PRIVATE_KEY_SECURITY;

PPKF pkfAlloc(int hash_id, 
			  int sign_id, 
			  int prng_id, 
			  char* email, 
			  char* organ, 
			  unsigned int end_time,
			  char* password, 
			  int crypt_id);

void pkfFree(PPKF pkf);

void pkfShow(PPKF pkf);

int pkfMakeKeyPair();

PPKF pkfMake(PPKF pkf, 
			 int make_key, 
			 char* public_key_path, 
			 char* private_key_path);

PPKF pkfSign(char* pkf_file, 
			 char* opk_file, 
			 PPKF_ISSUER issuer);

int pkfVerify(char* pkf_file, 
			  char* opp_file,
			  int* result);

int pkfReadPrivateKey(char* opk_file, 
					  char* private_out_file,
					  char* password);

int pkfReadPublicKey(char* opk_file, 
					 char* public_out_file);

int pkfReadIssuer(char* opk_file, 
				  PPKF_ISSUER issuer);

#endif
