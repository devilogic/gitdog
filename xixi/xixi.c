#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>

#include "version.h"
#include "pkf.h"
#include "xlicense.h"
#include "xcontent.h"
#include "tools.h"

#define NANAN_PATH                 "./nanan"
#define DEF_SIGN_ID                0
#define DEF_CRYPT_ID               6
#define DEF_HASH_ID                3
#define DEF_PRNG_ID                0
typedef struct _ARGUMENTS {
	int show_version;
	
	int make_pkf;
	int make_license;
	int sign_pkf;
	int verify_pkf;
	int show_pkf;
	int set_nanan;
	int import_root;
	int import_pkf;
	int show_xlice;
	int sign_xlice;
	int import_private_key;

	int crypt_id;
	int sign_id;
	int hash_id;
	int prng_id;

	char nanan_path[128];

	char pkf_path[128];

	union {
		char owner_private_key_path[128];
		char root_pkf_path[128];
	};

	char xlicense_path[128];
} ARGUMENTS, *PARGUMENTS;

char* g_nanan_path = NULL;

#if 0
ARGUMENTS g_arguments = {
	0,                /* show version */
	0,                /* make pkf */
	0,                /* make license */
    0,                /* sign pkf */
	0,                /* verify pkf */
	0,                /* show pkf */
	0,                /* set nanan path */
    0,                /* import root */
	0,                /* import pkf */
	0,                /* show xlicense */
	0,                /* sign xlicense */
	0,                /* import private key */
	DEF_CRYPT_ID,
	DEF_SIGN_ID,
	DEF_HASH_ID,
	DEF_PRNG_ID,
	{0},              /* nanan path */
	{0},              /* pkf path */
    {0},              /* root pkf,opk path */
	{0}               /* xlicense path */
};
#else
ARGUMENTS g_arguments;
#endif

void init_arguments(PARGUMENTS arg) {
	memset(arg, 0, sizeof(ARGUMENTS));
	arg->crypt_id = DEF_CRYPT_ID;
	arg->sign_id = DEF_SIGN_ID;
	arg->hash_id = DEF_HASH_ID;
	arg->prng_id = DEF_PRNG_ID;
}

void usage() {
	printf("xixi [options]\n");
	printf("[pkf]\n");
	printf("--make-pkf(-p) <pkf path> make pkf file\n");
	printf("--sign-pkf(-s) <pkf path> sign pkf file\n");
	printf("--verify-pkf(-v) <pkf path> verify pkf file\n");
	printf("--import-root-pkf <opk path> import root pkf file\n");
	printf("--show-pkf <pkf path> show pkf content\n");
	printf("\n");
	printf("[xlicense]\n");
	printf("--make-license(-l) <license path> make xlicense\n");
	printf("--sign-license(-x) <license path> sign xlicense\n");
	printf("--verify-license(-y) <license path> verify xlicense\n");
	printf("--show-license <license path> show xlicense\n");
	printf("--import-user-pkf <pkf path> import owner pkf\n");
	printf("--import-owner-pkf <pkf path> import pirvate key\n");
	printf("--import-private-key <pk path> import pirvate key\n");
	printf("--import-public-key <pk path> import public key\n");
	printf("--import-owner-pkf-id <owner id> import owner id\n");
	printf("--import-private-key-password <password> the password of pkf private key\n");
	printf("\n");
	printf("[xfile]\n");
	printf("--encrypt-file(-e) <file path> encrypt file\n");
	printf("--decrypt-file(-d) <file path> decrypt file\n");
	printf("--add-license-to-file <license path> add license to file\n");
	printf("--del-license-to-file <license path> del license to file\n");
	printf("--set-license-pool <path> set xlicense directory\n");
	printf("--set-target-file(-t) <file path> set target file\n");
	printf("\n");
	printf("select algorithm---\n");
	printf("--select-crypt(-1) <crypt id> select crypt algorithm\n");
	printf("--select-sign(-2) <sign id> select sign algorithm\n");
	printf("--select-hash(-3) <hash id> select hash algorithm\n");
	printf("--select-prng(-4) <prng id>> select random algorithm\n");
	printf("\n");
	printf("[misc]\n");
	printf("--set-nanan(-n) <nanan path> set nanan path\n");
	printf("--version show version\n");
	printf("\n");
	printf("http://www.4dogs.cn\n");
	printf("%s\n\n", XIXI_VERSION);
}

int handle_arguments(int argc, char* argv[]) {
	int opt,show_version, longidx;
	int import_root_pkf,show_pkf,show_license,
		import_user_pkf,import_owner_pkf,import_private_key,
		import_public_key,import_owner_pkf_id,import_private_key_password,
		encrypt_file,decrypt_file,
		add_license_to_file,del_license_to_file,
		set_license_pool,
		show_version;
	const char* short_opts = ":p:l:s:v:n:x:y:e:d:t:1:2:3:4:";
	struct option long_opts[] = {
		/*0*/{"make-pkf",1,NULL,'p'},
		/*1*/{"sign-pkf",1,NULL,'s'},
		/*2*/{"verify-pkf",1,NULL,'v'},
		/*3*/{"import-root-pkf",1,&import_root_pkf,0x2013},
		/*4*/{"show-pkf",1,&show_pkf,0x2012},
		/*5*/{"make-license",1,NULL,'l'},
		/*6*/{"sign-license",1,NULL,'x'},
		/*7*/{"verify-license",1,NULL,'y'},
		/*8*/{"show-license",1,&show_license,0x2011},
		/*9*/{"import-user-pkf",1,&import_user_pkf,0x2010},
		/*10*/{"import-owner-pkf",1,&import_owner_pkf,0x2009},
		/*11*/{"import-private-key",1,&import_private_key,0x2008},
		/*12*/{"import-public-key",1,&import_public_key,0x2007},
		/*13*/{"import-owner-pkf-id",1,&import_owner_pkf_id,0x2006},
		/*14*/{"import-private-key-password",1,&import_private_key_password,0x2005},
		/*15*/{"encrypt-file",1,&encrypt_file,0x2004},
		/*16*/{"decrypt-file",1,&decrypt_file,0x2003},
		/*17*/{"add-license-to-file",1,&add_license_to_file,0x2002},
		/*18*/{"del-license-to-file",1,&del_license_to_file,0x2001},
		/*19*/{"set-license-pool",1,&set_license_pool,0x2000},
		/*20*/{"set-target-file",1,NULL,'t'},
		/*21*/{"select-crypt",1,NULL,'1'},	    /* 选择加密算法 */
		/*22*/{"select-sign",1,NULL,'2'},		/* 选择签名算法 */
		/*23*/{"select-hash",1,NULL,'3'},		/* 选择哈希算法 */
		/*24*/{"select-prng",1,NULL,'4'},		/* 选择随机算法 */
		/*25*/{"set-nanan",1,NULL,'n'},
		/*26*/{"version",0,&show_version,0x1993},
		{0,0,0,0}
	};

	/* 初始化参数结构 */
	init_arguments(&g_arguments);

	while ((opt = getopt_long(argc, argv, short_opts, 
							  long_opts, &longidx)) != -1) {
		switch (opt) {
		case 0:
			if ((show_version == 0x2013) && (longidx == 5)) {
				g_arguments.show_version = 1;
			} else if ((import_root == 0x2012) && (longidx == 7)) {
				g_arguments.import_root = 1;
				strcpy(g_arguments.root_pkf_path,
					   optarg);
			} else if ((show_pkf == 0x2011) && (longidx == 4)) {
				g_arguments.show_pkf = 1;
				strcpy(g_arguments.pkf_path,
					   optarg);
			} else if ((import_pkf == 0x2010) && (longidx == 8)) {
				g_arguments.import_pkf = 1;
				strcpy(g_arguments.pkf_path,
					   optarg);
			} else if ((show_license == 0x2009) && (longidx == 9)) {
				g_arguments.show_xlice = 1;
				strcpy(g_arguments.xlicense_path,
					   optarg);
			} else if ((import_private_key == 0x2008) && (longidx == 11)) {
				g_arguments.import_private_key = 1;
				strcpy(g_arguments.owner_private_key_path,
					   optarg);
			}
			break;
		case 's':
			g_arguments.sign_pkf = 1;
			strcpy(g_arguments.pkf_path, optarg);
			break;
		case 'x':
			g_arguments.sign_xlice = 1;
			strcpy(g_arguments.xlicense_path, optarg);
			break;
		case 'v':
			g_arguments.verify_pkf = 1;
			strcpy(g_arguments.pkf_path, optarg);
			break;
		case 'p':
			g_arguments.make_pkf = 1;
			strcpy(g_arguments.pkf_path, optarg);
			break;
		case 'l':
			g_arguments.make_license = 1;
			strcpy(g_arguments.xlicense_path, optarg);
			break;
		case 'n':
			g_arguments.set_nanan = 1;
			strcpy(g_arguments.nanan_path, optarg);
			break;
		case '4':
			g_arguments.prng_id = atoi(optarg);
			break;
		case '3':
			g_arguments.hash_id = atoi(optarg);
			break;
		case '2':
			g_arguments.sign_id = atoi(optarg);
			break;
		case '1':
			g_arguments.crypt_id = atoi(optarg);
			break;
		case '?':
			printf("unknow options: %c\n", optopt);
			return 1;
			break;
		case ':':
			printf("option need a option\n");
			return 1;
			break;
		}
	}

	return 0;
}

static PPKF read_pkf_configure_from_stdin(int* make_key, 
										  char* public_key_path,
										  char* private_key_path) {
	int err, c;
	PPKF pkf;
	int hash_id, sign_id, prng_id, crypt_id;
	char password[128];
	int end_data;
	char* s;
	char email[128];
	char organ[128];
	char buffer[128];

	printf("email:");
	s = gets(email);
	printf("organization:");
	s = gets(organ);
	printf("hash algorithm:");
	s = gets(buffer);
	hash_id = atoi(buffer);
	printf("sign algorithm:");
	s = gets(buffer);
	sign_id = atoi(buffer);
	printf("prng algorithm:");
	s = gets(buffer);
	prng_id = atoi(buffer);

	{	
		/* 到期日期 */
		struct tm now = {0};

		printf("end time--\n");
		printf("\tyear:");
		s = gets(buffer);
		now.tm_year = atoi(s) - 1900;
		printf("\tmoon:");
		s = gets(buffer);
		now.tm_mon = atoi(s);
		printf("\tday:");
		s = gets(buffer);
		now.tm_mday = atoi(s);
		end_data = mktime(&now);
	}

	printf("make key?:");
	s = gets(buffer);
	if (strlen(buffer)) *make_key = 1;
	else *make_key = 0;
	//printf("crypt private key:");
	//s = gets(buffer);
	//if (strlen(buffer)) {
	printf("crypt private key algorithm:");
	s = gets(buffer);
	crypt_id = atoi(buffer);
	printf("password(max 32 character):");
	s = gets(buffer);
	strcpy(password, buffer);
	//}
	if (!*make_key) {
		printf("public key path:");
		s = gets(buffer);
		if (strlen(buffer)) strcpy(public_key_path, buffer);
		else strcpy(public_key_path, "./public.key");

		printf("private key path:");
		s = gets(buffer);
		if (strlen(buffer)) strcpy(private_key_path, buffer);
		else strcpy(private_key_path, "./private.key");

	} else {
		strcpy(private_key_path, "./private.key");
		strcpy(public_key_path, "./public.key");
	}

	pkf = pkfAlloc(hash_id, 
				   sign_id, 
				   prng_id, 
				   email, 
				   organ, 
				   end_data,
				   password,
				   crypt_id);

	return pkf;
}

#define check_nanan(nanan_path) exist_file(nanan_path)
int main(int argc, char* argv[]) {
	int err, make_key;
	PPKF pkf;
	PXLICENSE xlice;

	if (argc == 1) {
		usage();
		return 0;
	}

	err = handle_arguments(argc, argv);
	if (err != 0) {
		return 1;
	}

	if (strlen(g_arguments.nanan_path) == 0) {
		g_nanan_path = NANAN_PATH;
	} else {
		g_nanan_path = g_arguments.nanan_path;
	}

	if (check_nanan(g_nanan_path) == 0) {
		printf("[-] nanan not exist\n");
		return 1;
	}

	/* 处理命令行 */
	if (g_arguments.show_version) {
		printf("%s\n", XIXI_VERSION);
	} else if (g_arguments.show_pkf) {
		unsigned char* tmp;
		unsigned long tmpsize;

		err = read_file(g_arguments.pkf_path,
						&tmp,
						&tmpsize);
		if (err != 0) {
			printf("[-] read pkf file%s error\n", g_arguments.pkf_path);
			return 1;
		}

		pkf = (PPKF)tmp;
		pkfShow(pkf);
		free(tmp);
	} else if (g_arguments.show_xlice) {
		unsigned long xlice_size;
		int err;

		err = read_file(g_arguments.xlicense_path,
						(unsigned char**)&xlice,
						&xlice_size);
		if (err != 0) {
			printf("[-] read xlicense file%s error\n", g_arguments.xlicense_path);
			return 1;
		}

		xliceShow(xlice);
		xliceFree(xlice);
	} else if (g_arguments.make_pkf) {
		int err;
		char private_key_path[256];
		char public_key_path[256];

		err = 0;
		make_key = 0;
		pkf = read_pkf_configure_from_stdin(&make_key,
											public_key_path,
											private_key_path);
		if (pkf == NULL) {
			printf("[-] make pkf header error\n");
			return 1;
		}

		pkf = pkfMake(pkf, 
					  make_key, 
					  public_key_path,
					  private_key_path);

		if (!pkf) {
			printf("[-] pkf make error\n");
			return 1;
		}

		/* 写入文件 */
		{
#if 0
			/* 使用直接的write_file来写入文件 */
			FILE* fp;
			int total;

			fp = fopen(g_arguments.pkf_path, "wb");
			if (!fp) {
				printf("[-] create pkf file error\n");
				goto _error;
			}
			total = pkf->file_size;
			if ((err = fwrite((unsigned char*)pkf,
							  1, 
							  total, 
							  fp)) != total) {
				printf("[-] write pkf error\n");
				pkfFree(pkf);
				return 1;
			}
			fclose(fp);
#else
			err = write_file(g_arguments.pkf_path,
							 (unsigned char*)pkf,
							 pkf->file_size);
			if (err != 0) {
				printf("[-] write pkf error\n");
				pkfFree(pkf);
				return 1;
			}
#endif
			printf("\n");
			pkfShow(pkf);
			pkfFree(pkf);
		}
	} else if (g_arguments.make_license) {
		int err;
		PXLICENSE xlice;
		
		if (!g_arguments.import_pkf) {
			printf("[-] not import pkf\n");
			return 1;
		}
		
		xlice = xliceAlloc(g_arguments.crypt_id,
						   g_arguments.sign_id,
						   g_arguments.hash_id,
						   g_arguments.prng_id);

		if (!xlice) {
			printf("[-] alloc xlicense memory error\n");
			return 1;
		}
		
		err = xliceSetPKF(&xlice,
						  g_arguments.pkf_path);
		if (err != 0) {
			xliceFree(xlice);
			printf("[-] set pkf error\n");
			return 1;
		}

		err = write_file(g_arguments.xlicense_path,
						 (unsigned char*)xlice,
						 xlice->file_size);
		if (err != 0) {
			xliceFree(xlice);
			printf("[-] write xlicense file:%s error\n",
				   g_arguments.xlicense_path);
			return 1;
		}

		xliceFree(xlice);
	} else if (g_arguments.sign_xlice) {
		if (g_arguments.import_private_key == 0) {
			printf("[-] not import owner private key\n");
			return 1;
		}

		err = xliceSignIt(g_arguments.owner_private_key_path,
						  g_arguments.xlicense_path);
		if (err != 0) {
			printf("[-] sign xlicense file:%s error\n",
				   g_arguments.xlicense_path);
		}
	} else if (g_arguments.verify_pkf) {
		PPKF pkf;
		FILE* fp;
		int err, result;
		char public_out_file[256];

		if (!g_arguments.import_root) {
			printf("[-] not import root pkf\n");
			return 1;
		}

		err = pkfReadPublicKey(g_arguments.root_pkf_path,
							   public_out_file);

		if (err != 0) {
			printf("[-] read public key error\n");
			return 1;
		}

		err = pkfVerify(g_arguments.pkf_path, 
						public_out_file,
						&result);
		if (err != 0) {
			if (err == 2) {
				printf("[-] pkf:%s is not has sign\n",
					   g_arguments.pkf_path);
			} else {
				printf("[-] verify error\n");
			}
		}
		delete_file(public_out_file);

		if (result) {
			printf("[+] verify success\n");
		} else {
			printf("[-] verify failed\n");
		}
		
	} else if (g_arguments.sign_pkf) {
		PPKF pkf;
#if 0
		FILE* fp;
#endif
		int err;
		PKF_ISSUER issuer;
		char private_out_file[256];
		char password[128];
		char* s;
		
		memset(&issuer, 0, sizeof(PKF_ISSUER));

		if (!g_arguments.import_root) {
			printf("[-] not import root pkf\n");
			return 1;
		}

		err = pkfReadIssuer(g_arguments.root_pkf_path,
							&issuer);
		if (err != 0) {
			printf("[-] read issuer info error\n");
			return 1;
		}

		/* 读取密码 */
	_reinput:
		memset(password, 0, 128);
		printf("please input private key password:");
		gets(password);
		if (strlen(password) == 0) goto _reinput;

		err = pkfReadPrivateKey(g_arguments.root_pkf_path,
								private_out_file,
								password);
		if (err != 0) {
			printf("[-] read private key error\n");
			return 1;
		}

		pkf = pkfSign(g_arguments.pkf_path, 
					  private_out_file,
					  &issuer);

		delete_file(private_out_file);

		if (!pkf) {
			printf("[-] sign pkf error\n");
			return 1;
		}

#if 0
		/* 我写这段的时候，肯定也是在犯鼻炎 */
		fp = fopen(g_arguments.pkf_path, "wb");
		if (!fp) {
			printf("[-] open pkf file:%s failed\n", g_arguments.pkf_path);
			pkfFree(pkf);
			return 1;
		}

		err = fwrite((unsigned char*)pkf, 1, pkf->file_size, fp);
		if (err != pkf->file_size) {
			printf("[-] write pkf file:%s failed\n", g_arguments.pkf_path);
			pkfFree(pkf);
			return 1;			
		}
		fclose(fp);
#endif

		pkfShow(pkf);
		pkfFree(pkf);
	}

	return 0;

 _error:
	if (pkf) pkfFree(pkf);
	return 1;
}
