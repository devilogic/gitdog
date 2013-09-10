/**
 * @file nanan.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
//#define _GNU_SOURCE		/* 为了支持getopt_long */
#include <getopt.h>

#include <tomcrypt.h>

#include "nanan.h"
#include "tools.h"

#if defined(APPLICATION)

#define OPT_MAKEY		1		/* 生成公私钥对 */
#define OPT_SIGN		2		/* 对目标进行签名 */
#define OPT_SIGN_VERIFY 4       /* 对目标进行签名确认 */
#define OPT_ENCRYPT		8		/* 对目标进行加密 */
#define OPT_DECRYPT		16		/* 对目标进行解密 */
#define OPT_HASH		32		/* 对目标进行摘要计算 */

typedef struct _ARGUMENTS {
	int show_config;
	int show_version;
	int silent;

	int sign_algorithm;		/* 签名算法 */
	int crypt_algorithm;	/* 加密算法 */
	int hash_algorithm;		/* 哈希算法 */
	int prng_algorithm;		/* 随机算法 */

	int options;			/* 要设定的选项 */

	int crypt_mode;         /* 加密算法模式 */

	char key_path[256];		/* 公私钥输出路径 */
	
	char crypt_key[512];	/* 加解密码 */
	char IV[512];			/* 初始化值 */

	int file_count;			/* 文件个数 */
	char* files[256];		/* 文件路径 */	

	int crypt_print_mode;		/* 加解密输出模式 */
	int crypt_symmetric_mode;	/* 加密模式 */
		
	int show_hashsize;
	int show_crypt_ivsize; 

	int import_public_key;
	char public_key_file[256];

	int import_private_key;
	char private_key_file[256];

	int import_sign;
	char sign_file[256];

	int is_output;
	char output[256];		/* 输出结果文件 */
	
	int is_input;
	char input[256];
} ARGUMENTS, *PARGUMENTS;

ARGUMENTS g_arguments = {
	0,			/* show arguments */
	0,			/* show version */
	0,          /* slient */
	0,			/* rsa */
	6,			/* aes */
	2,			/* sha1 */
	0,			/* yarrow */
	0,			/* options */
	CTR_MODE,   /* ctr mode */
	{0},		/* key path */
	{0},		/* crypt key */
	{0},		/* IV */
	0,			/* file count */
	{0},		/* files */
	0,			/* crypt print mode */
	CTR_MODE,	/* symmetric mode */
	0,			/* show hashsize */
	0,			/* show crypt ivsize */
	0,          /* import public key */
	{0},        /* public key */
	0,          /* import private key */
	{0},        /* private key */
	0,          /* import sign */
	{0},        /* sign */
	0,			/* is output */
	{0},		/* output */
	0,          /* is input */
	{0}         /* input */
};

#if 0
void show_arguments() {
	int i;
	printf("sign = %d\n", g_arguments.sign_algorithm);
	printf("crypt = %d\n", g_arguments.crypt_algorithm);
	printf("hash = %d\n", g_arguments.hash_algorithm);
	printf("prng = %d\n", g_arguments.prng_algorithm);

	printf("options = %04x\n", g_arguments.options);
	printf("key path= %s\n", g_arguments.key_path);
	printf("crypt key = %s\n", g_arguments.crypt_key);
	for (i = 0; i < g_arguments.file_count; i++)
		printf("file[%d] = %s\n", i, g_arguments.files[i]);

	printf("crypt print mode = %s\n", g_arguments.crypt_print_mode ? "text" : "hex");
	printf("show hashsize = %s\n", g_arguments.show_hashsize ? "on" : "off");
	printf("show crypt ivsize = %s\n", g_arguments.show_crypt_ivsize ? "on" : "off");

	if (g_arguments.is_output)
		printf("output file = %s\n", g_arguments.output);
}
#endif

void usage() {
	printf("salamis [commands] [file,...]\n");
	printf("[commands]\n");
	printf("encode algorithm---\n");
	//printf("--encode(-x) encode something\n");
	//printf("--decode(-z) decode something\n");
	printf("\n");
	printf("sign algorithm---\n");
	printf("--makey(-m) <path> make public && private key\n");
	printf("--sign(-s) sign something\n");
	printf("--verify(-v) verify sign\n");
	printf("--import-sign <sign> import sign\n");
	printf("--import-public-key <key> import public key\n");
	printf("--import-private-key <key> import private key\n");
	printf("\n");
	printf("hash algorithm---\n");
	printf("--hash(-h) hash something\n");
	printf("\n");
	printf("crypt algorithm---\n");
	printf("--encrypt(-e) <key> encrypt something\n");
	printf("--decrypt(-d) <key> decrypt something\n");
	printf("--setup-crypt-print-mode <0:hex,1:text>\n");
	//printf("--setup-crypt-symmetric-mode <mode>\n");
	printf("\n");
	printf("select algorithm---\n");
	printf("--select-crypt(-1) <crypt id> select crypt algorithm\n");
	printf("--select-sign(-2) <sign id> select sign algorithm\n");
	printf("--select-hash(-3) <hash id> select hash algorithm\n");
	printf("--select-prng(-4) <prng id>> select random algorithm\n");
	printf("--setect-crypt-mode(-5) <mode id> select crypt mode\n");
	printf("\n");

	printf("misc---\n");
	//printf("--show-config show arguments\n");
	printf("--output(-o) [file] print orig result to file\n");
	printf("--silent run on silent\n");
	printf("--version show version\n");
	printf("\n");
	printf("algorithm list---\n");
	printf("[hash algorithm]\n");
	hashPrintAlgorithm(1);
	printf("\n");
	printf("[sign algorithm]\n");
#if defined(SALAMIS_VER_3_1)
	printf("<!!!>JUST SUPORT RSA\n");
#endif
	signPrintAlgorithm(1);
	printf("\n");
	printf("[crypt algorithm]\n");
	cryptPrintAlgorithm(1);
	printf("\n");
	printf("[random algorithm]\n");
	randomPrintAlgorithm(1);
	printf("\n");
	printf("[crypt mode]\n");
#if defined(SALAMIS_VER_3_1)
	printf("<!!!>F8,XTS mode is not test passed in this version\n");
#endif
	cryptPrintMode(1);
	printf("\n");
	printf("http://www.4dogs.cn\n");
	printf("%s\n\n", SALAMIS_VERSION);
}

int handle_arguments(int argc, char* argv[]) {
	int opt, i;
	int setup_crypt_print_mode = 0, show_hashsize = 0, show_crypt_ivsize = 0;
	int show_config = 0, show_version = 0, setup_crypt_symmetric_mode = 0;
	int import_public_key = 0, import_private_key = 0, import_sign;
	int silent = 0;
	int longidx;
	const char* short_opts = ":i:o:m:hsve:d:1:2:3:4:5:";
	struct option long_opts[] = {
		/*0*/{"input",1,NULL,'i'},           /* 读入数据 */
		/*1*/{"output",1,NULL,'o'},			/* 输出结果 */
		/*2*/{"makey",1,NULL,'m'},			/* 密钥生成 */
		/*3*/{"hash",0,NULL,'h'},			/* 哈希 */
		/*4*/{"sign",0,NULL,'s'},			/* 签名 */
		/*5*/{"verify",0,NULL,'v'},          /* 验证签名 */
		/*6*/{"encrypt",1,NULL,'e'},			/* 加密算法 */
		/*7*/{"decrypt",1,NULL,'d'},			/* 解密算法 */
		/*8*/{"import-public-key",1,&import_public_key, 0x1990},
		/*9*/{"import-private-key",1,&import_private_key, 0x1991},
		/*10*/{"import-sign",1,&import_sign,0x1997},
		/*11*/{"setup-crypt-print-mode",1,&setup_crypt_print_mode,0x1983},
		/*12*/{"setup-crypt-symmetric-mode",1,&setup_crypt_symmetric_mode,0x1204},
		/*13*/{"show-hashsize",0,&show_hashsize,0x1210},
		/*14*/{"show-crypt-ivsize",0,&show_crypt_ivsize,0x1993},
		/*15*/{"select-crypt",1,NULL,'1'},	/* 选择加密算法 */
		/*16*/{"select-sign",1,NULL,'2'},		/* 选择签名算法 */
		/*17*/{"select-hash",1,NULL,'3'},		/* 选择哈希算法 */
		/*18*/{"select-prng",1,NULL,'4'},		/* 选择随机算法 */
		/*19*/{"show-config",0,&show_config,0x2012},
		/*20*/{"version",0,&show_version,0x2013},
		/*21*/{"silent",0,&silent,0x1998},
		/*22*/{"select-crypt-mode",1,NULL,'5'}, /* 选择加密模式 */
		{0,0,0,0}
	};

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, &longidx)) != -1) {
		switch (opt) {
		case 0:
			if ((setup_crypt_print_mode == 0x1983) && (longidx == 11))
				g_arguments.crypt_print_mode = atoi(optarg);
			else if (show_hashsize == 0x1210)
				g_arguments.show_hashsize = 1;
			else if (show_crypt_ivsize == 0x1993)
				g_arguments.show_crypt_ivsize = 1;
			else if (show_config == 0x2012)
				g_arguments.show_config = 1;
			else if (show_version == 0x2013)
				g_arguments.show_version = 1;
			else if (setup_crypt_symmetric_mode == 0x1204)
				g_arguments.crypt_symmetric_mode = 1;
			else if ((import_public_key == 0x1990) && (longidx == 8)) {
				g_arguments.import_public_key = 1;
				strcpy(g_arguments.public_key_file, optarg);
			} else if ((import_private_key == 0x1991) && (longidx == 9)) {
				g_arguments.import_private_key = 1;
				strcpy(g_arguments.private_key_file, optarg);
			} else if ((import_sign == 0x1997) && (longidx == 10)) {
				g_arguments.import_sign = 1;
				strcpy(g_arguments.sign_file, optarg);
			} else if ((silent == 0x1998) && (longidx == 21)) {
				g_arguments.silent = 1;
			}
			break;
		case 'i':
			g_arguments.is_input = 1;
			strcpy(g_arguments.input, optarg);
			break;
		case 'o':
			g_arguments.is_output = 1;
			//if (strlen(optarg) != 0)
			strcpy(g_arguments.output, optarg);
			break;
		case 'm':
			g_arguments.options |= OPT_MAKEY;
			strcpy(g_arguments.key_path, optarg);
			break;
		case 'h':
			g_arguments.options |= OPT_HASH;
			break;
		case 's':
			g_arguments.options |= OPT_SIGN;
			break;
		case 'v':
			g_arguments.options |= OPT_SIGN_VERIFY;
			break;
		case 'e':
			g_arguments.options |= OPT_ENCRYPT;
			//if (strlen(optarg) != 0)
			strcpy(g_arguments.crypt_key, optarg);
			break;
		case 'd':
			g_arguments.options |= OPT_DECRYPT;
			//if (strlen(optarg) != 0)
			strcpy(g_arguments.crypt_key, optarg);
			break;
		case '5':
			g_arguments.crypt_mode = atoi(optarg);
			break;
		case '4':
			g_arguments.prng_algorithm = atoi(optarg);
			break;
		case '3':
			g_arguments.hash_algorithm = atoi(optarg);
			break;
		case '2':
			g_arguments.sign_algorithm = atoi(optarg);
			break;
		case '1':
			g_arguments.crypt_algorithm = atoi(optarg);
			break;
		case '?':
			printf("unknow options: %c\n", optopt);
			return -1;
			break;
		case ':':
			printf("option need a option\n");
			return -1;
			break;
		}
	}/* end while */

	if (!(g_arguments.options & OPT_HASH))
		g_arguments.show_hashsize = 0;

	if (!(g_arguments.options & OPT_DECRYPT))
		g_arguments.show_crypt_ivsize = 0;

	g_arguments.file_count = argc - optind;
	for (i = 0; optind < argc; optind++, i++) {
		g_arguments.files[i] = (char*)malloc(256);
		strcpy(g_arguments.files[i], argv[optind]);
	}

	return 0;
}

void free_arguments() {
	int x;
	for (x = 0; x < g_arguments.file_count; x++) {
		free(g_arguments.files[x]);	
		g_arguments.files[x] = NULL;
	}
	g_arguments.file_count = 0;
}

void at_exit() {
	free_arguments();
}

void output_result(unsigned char* buffer, unsigned long buffer_size) {
	if (g_arguments.is_output) {
		FILE *fp = fopen(g_arguments.output, "wb");
		if (fp == NULL) {

			if (!g_arguments.silent)
				printf("[-] output result[%s] error\n", g_arguments.output);
			exit(-1);
		}
		
		fwrite(buffer, 1, buffer_size, fp);
		fclose(fp);
	}
}

static int read_sign_file(char* sigfile, 
						  unsigned char** sigdata, unsigned long* sigsize) {
	FILE* fp;
	int err;

	fp = fopen(sigfile, "rb");
	if (!fp) return 1;
	
	fseek(fp, 0, SEEK_END);
	err = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	*sigdata = (unsigned char*)malloc(err);
	if (!*sigdata) {
		fclose(fp);
		return 1;
	}
	*sigsize = err;

	err = fread(*sigdata, 1, err, fp);
	if (err != *sigsize) {
		free(*sigdata);
		fclose(fp);
		return 1;
	}

	fclose(fp);
	return 0;
}

int main(int argc, char* argv[]) {
	int ret = 0, e;
	char error_string[256] = {0};

	atexit(at_exit);

	/* 初始化算法 */
	if (((e = randomInit()) != CRYPT_OK) || 
		((e = hashInit()) != CRYPT_OK) ||
		((e = cryptInit()) != CRYPT_OK) ||
		((e = signInit()) != CRYPT_OK)) {

		if (!g_arguments.silent)
			printf("[-] init error(%d) - %s\n", e, error_2_string(e));

		return 1;
	}

	if (argc == 1) {
		usage();
		return 0;
	}

	/* 分析命令行 */
	ret = handle_arguments(argc, argv);
	if (ret) return 1;	

	/* 一些辅助功能 */
	if (g_arguments.options == 0) {
		if (g_arguments.show_version) {

			if (!g_arguments.silent)
				printf("%s\n", SALAMIS_VERSION);

		}

		return 0;
	}

#if 0
	if (g_arguments.show_config)
		show_arguments();
#endif
 
	if (g_arguments.options & OPT_MAKEY) {
		PSIGN_ALGORITHM sign = signAlloc(g_arguments.sign_algorithm,
										 g_arguments.prng_algorithm,
										 g_arguments.hash_algorithm,
										 g_arguments.crypt_algorithm);
		if ((e = signMakePK(sign, g_arguments.key_path)) == 0) {
			signPrintKey(sign); 
		} else {
			if (!g_arguments.silent)
				printf("[-] make public & private key error(%d) : %s\n", e, error_2_string(e));
		}
		
		signFree(sign);
		
	} else if (g_arguments.options & OPT_HASH) {
		int i;
		PHASH_ALGORITHM hash = hashAlloc(g_arguments.hash_algorithm);
		if ((e = hashRun(hash, 
						 (int)(g_arguments.file_count == 0),
						 (char**)(g_arguments.files), 
						 g_arguments.file_count)) == 0) {

			if (g_arguments.show_hashsize) 
				if (!g_arguments.silent) 
					printf("%d\n", (int)(hash->hash_size));

			if (!g_arguments.silent)
				hashPrintResult(hash);

			/* 输出结果 */
			if (g_arguments.is_output) {
				if (g_arguments.file_count == 0) {
					output_result(hash->result[0], hash->hash_size);
				} else {
					for (i = 0; i < g_arguments.file_count; i++)
						output_result(hash->result[i], hash->hash_size);
				}
			}

		} else {
			if (!g_arguments.silent)
				printf("[-] hash error(%d) : %s\n", e, error_2_string(e));
		}
		hashFree(hash);
	} else if ((g_arguments.options & OPT_SIGN) || 
			   (g_arguments.options & OPT_SIGN_VERIFY)) {
		unsigned char* sigdata;
		unsigned long sigsize;
		PSIGN_ALGORITHM sign = signAlloc(g_arguments.sign_algorithm,
										 g_arguments.prng_algorithm,
										 g_arguments.hash_algorithm,
										 g_arguments.crypt_algorithm);
		if ((g_arguments.import_public_key + 
			 g_arguments.import_private_key) == 0) {
			if (!g_arguments.silent)
				printf("[-] import public | private key at least\n");
			return 1;
		}

		/* 导入密钥 */
		if (g_arguments.import_public_key) {
			if ((e = signImportKey(sign, 
								   PK_PUBLIC, 
								   g_arguments.public_key_file)) != CRYPT_OK) {
				if (!g_arguments.silent)
					printf("[-] import public key error(%d) : %s\n", e, 
						   error_2_string(e));
				return e;
			}
		}
		if (g_arguments.import_private_key) {
			if ((e = signImportKey(sign, 
								   PK_PRIVATE, 
								   g_arguments.private_key_file)) != CRYPT_OK) {
				if (!g_arguments.silent)
					printf("[-] import private key error(%d) : %s\n", e, 
						   error_2_string(e));
				return e;
			}
		}

		/* 检查参数 */
		if (g_arguments.options & OPT_SIGN) {
			/* 签名运算 */
			if (g_arguments.import_private_key == 0) {
				if (!g_arguments.silent)
					printf("[-] miss private key\n");
				return 1;
			}
			sigdata = NULL;
			sigsize = 0;
		} else {  /* OPT_SIGN_VERIFY */
			/* 验证运算 */
			if (g_arguments.import_public_key == 0) {
				if (!g_arguments.silent)
					printf("[-] miss public key\n");
				return 1;
			}

			if (g_arguments.import_sign == 0) {
				if (!g_arguments.silent)
					printf("[-] miss sign\n");
				return 1;
			}

			/* 读取签名数据 */
			e = read_sign_file(g_arguments.sign_file,
							   &sigdata, &sigsize);
			if (e != 0) {
				printf("[-] get signature data failed\n");
				return 1;
			}
		}

		if ((e = signSignVerify(sign, 
								(int)(g_arguments.file_count == 0 ? 1 : 0),
								(g_arguments.options & OPT_SIGN_VERIFY),
								g_arguments.files[0], 
								0,
								sigdata, 
								sigsize)) == CRYPT_OK) {
			/* 打印结果 */
			if (g_arguments.options & OPT_SIGN_VERIFY) {
				if (!g_arguments.silent) {
					if (sign->verify_result)
						printf("[+] verify success\n");
					else
						printf("[-] verify failed\n");
				}
			} else { /* 签名 */
				if (!g_arguments.silent)
					signPrintSign(sign);
				output_result(sign->result, sign->result_size);
			}
		} else {
			if (g_arguments.options & OPT_SIGN) {
				if (!g_arguments.silent)
					printf("[-] sign error(%d) : %s\n", e, error_2_string(e));
				return e;
			} else {
				if (!g_arguments.silent)
					printf("[!] verify failed(%d) : %s\n", e, error_2_string(e));
				return e;
			}
		}
		
		signFree(sign);
	} else if ((g_arguments.options & OPT_DECRYPT) || 
			   (g_arguments.options & OPT_ENCRYPT)) {
		PCRYPT_ALGORITHM crypt = cryptAlloc(g_arguments.crypt_algorithm,
											g_arguments.crypt_mode,
											g_arguments.hash_algorithm,
											g_arguments.prng_algorithm,
											g_arguments.crypt_key);

		if ((e = cryptRun(crypt, 
						  (int)(g_arguments.file_count == 0),
						  (g_arguments.options & OPT_ENCRYPT), 
						  g_arguments.files[0])) == 0) {
	
			if (g_arguments.show_crypt_ivsize) 
				if (!g_arguments.silent)
					printf("%ud\n", crypt->iv_size);
			if (!g_arguments.silent)
				cryptPrintResult(crypt, g_arguments.crypt_print_mode);
			output_result(crypt->result, crypt->result_size);
		} else if (e != -1) {
			if (!g_arguments.silent)
				printf("[-] crypt error(%d) : %s\n", e, error_2_string(e));
			return e;
		} else {
			if (!g_arguments.silent)
				printf("[-] crypt error\n");
			return 1;
		}
	} else {
		if (!g_arguments.silent)
			printf("[-] error\n");
		return 1;
	}

	return 0;
}

#endif
