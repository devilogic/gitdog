#if !defined(__XLICENSE_H__)
#define __XLICENSE_H__

#include "pkf.h"

#define XLICE_PROP_NOT_AUTHED                    0x01
#define XLICE_PROP_AUTHED                        0x02
#define XLICE_PROP_0                             0x04         /* 自己的执照 */
#define XLICE_PROP_3                             0x08         /* 用于交换的执照 */

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
 * 1.用自己公钥证书字符串形式 + password字段的HASH值的字符串作为密码进行加解密
 */
typedef struct _XLICENSE {
	unsigned int magic;
	unsigned int version;
	unsigned char checksum[16];

	/* 以下部分是owner进行签名的部分 */

	char project_name[128];
	unsigned char project_hash[16];               /* owner的license的sha1值 */

	unsigned int property;
	unsigned int xchange_size;                    /* 相互交换的数据大小 */
	unsigned int xchange_sign_size;               /* xchange的签名大小 */

	unsigned int sign_size;                       /* owner的签名 */

	char password[128];                           /* 授权文件加密其他文件时使用的密码 */

	int crypt_id;                                 /* 使用什么加密算法 */
	int hash_id;                                  /* 使用什么HASH算法 */

	/* 保存了公钥的证书(属主) */
	PKF pfk;
	
	/* 以上部分是owner进行签名的部分 */

	/* 跟随一个owner的签名 */
    /* 跟随一组xchange数据(xchange_count个XID) */
	/* 跟随xchange的owner的签名 */
} XLICENSE, *PXLICENSE;

#endif
