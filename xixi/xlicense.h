/*
 * 执照的作用
 * 1.验证一个文件是否属于这个项目                       用owner的执照验证
 * 2.用于加密或者解密一个属于这个项目的文件               用不同用户的执照家解密
 * 3.用于确定这个项目有多少个维护者                     用owner的执照验证
 */
#if !defined(__XLICENSE_H__)
#define __XLICENSE_H__

#include "pkf.h"

#define XLICE_MAGIC                             0x1993
#define XLICE_VERSION                           0x0001

#define XLICE_PROP_AUTHED                        0x01
#define XLICE_PROP_0                             0x02         /* owner执照 */

#if !defined(LARGE_XCHANGE_NODE)
#define MAX_XCHANGE_NODE                         32           /* 一个项目组内的最大人数 */
#else
#define MAX_XCHANGE_NODE                         128
#endif

#define xlice_check_magic(x) (x->magic == XLICE_MAGIC)
#define xlice_check_version(x) (x->version == XLICE_VERSION)

typedef struct _XLICENSE {
	unsigned int magic;
	unsigned int version;
	unsigned int file_size;
	unsigned int sign_size;                       /* owner的签名 */
	unsigned char checksum[16];

	/* 以下部分是owner进行签名的部分 */

	union {
		unsigned int property;
		unsigned int sign_start;
		unsigned int checksum_start;
	};
#if defined(WITH_PROJECT_NAME)
	char project_name[64];                        /* 从owner的license的名称中复制 */
#endif
	XID owner_id;                                 /* owner的license的XID,如果是owner此项全0 */
	XID id;                                       /* 当前license的ID */

	int crypt_id;                                 /* 加密算法ID */
	PPKF pkf;                                     /* 临时使用一下 */

	/* 保存了公钥的证书(属主) */
	/*PKF pfk;*/
	
	/* 跟随一个owner的签名 */
} XLICENSE, *PXLICENSE;

PXLICENSE xliceAlloc(int crypt_id);

int xliceFree(PXLICENSE xlice);

int xliceSetPKF0(PXLICENSE* xlice, 
				 PPKF pkf);

int xliceSetPKF(PXLICENSE* xlice, 
				char* pkf_path);

#if defined(WITH_PROJECT_NAME)
int xliceSetProjectName(PXLICENSE xlice,
						char* project_name);

int xliceSetProjectName2(PXLICENSE xlice,
						 char* user_xlice_file);
#endif

int xliceSignIt0(char* owner_private_key, 
				 char* user_xlice_file,
				 PXLICENSE* xlice);

int xliceSignIt(char* owner_pkf_path,
				char* user_xlice_file,
				char* password);

void xliceShow(PXLICENSE xlice);

int xliceVerify(char* owner_pkf_path,
				char* user_xlice_file,
				int* result);

#endif
