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

typedef struct _XCHANGE_ID {
	int invalid;
	XID id;                                       /* XL的ID */
} XCHANGE_ID;

typedef struct _XCHANGE_LIST {
	unsigned int xchange_node_count;
	XCHANGE_ID list[MAX_XCHANGE_NODE];
	unsigned int xchange_sign_size;               /* xchange的签名大小 */
	/* 跟随一个签名 */
} XCHANGE_LIST;

#define xchange_list_size(n) (sizeof(XCHANGE_LIST) + n->xchange_sign_size);

/*
 * XLICENSE用于在一个项目，加解密文件与核实用户身份
 * 执照的生成：
 * 1.用户自己生成一个test.xlice的文件
 * 2.交给项目的owner，owner进行签名，证明其有效性
 * 3.owner将自身与用户设定到xchange链上
 * 4.如果用户想要与其他用户合作，则和其他用户商量好后，一同将自己的xlice
 * 交给项目owner,owner对其进行设定链操作
 * 
 * 加解密操作：
 * 1.使用XL文件进行加密
 */
typedef struct _XLICENSE {
	unsigned int magic;
	unsigned int version;
	unsigned int file_size;
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

	unsigned int xchange_count;                   /* 有多少个交换链 */
	unsigned int sign_size;                       /* owner的签名 */
	int sign_id;
	int hash_id;                                  /* HASH算法ID */
	int crypt_id;                                 /* 加密算法ID */
	int prng_id;                                  /* 随机算法ID */

	/* 保存了公钥的证书(属主) */
	/*PKF pfk;*/
	
	/* 跟随一个owner的签名 */
    /* 跟随一组xchange数据(xchange_count个结构) */
} XLICENSE, *PXLICENSE;

PXLICENSE xliceAlloc(int crypt_id,
					 int sign_id,
					 int hash_id,
					 int prng_id);

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

int xliceSetOwnerID(PXLICENSE xlice,
					unsigned char* owner_id);

int xliceSignIt0(char* owner_private_key, 
				 PXLICENSE xlice);

int xliceSignIt(char* owner_private_key,
				char* user_xlice_file);

void xliceShow(PXLICENSE xlice);

#endif
