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
typedef struct _ARGUMENTS {
	int show_version;
	
	int make_pkf;
	int make_license;
	int sign_pkf;
	int verify_pkf;
	int show_pkf;
	int set_nanan;
	int import_root;

	char nanan_path[128];
	char pkf_path[128];
	char root_pkf_path[128];
} ARGUMENTS, *PARGUMENTS;

ARGUMENTS g_arguments = {
	0,                /* show version */
	0,                /* make pkf */
	0,                /* make license */
    0,                /* sign pkf */
	0,                /* verify pkf */
	0,                /* show pkf */
	0,                /* set nanan path */
    0,                /* import root */
	{0},              /* nanan path */
	{0},              /* pkf path */
    {0}               /* root pkf */
};

void usage() {
	printf("xixi [options]\n");
	printf("--make-pkf(-p) <pkf path> make pkf file\n");
	printf("--make-license(-l) <pkf path>\n make xlincense");
	printf("--sign-pkf(-s) <pkf path> sign pkf file\n");
	printf("--verify-pkf(-v) <pkf path> verify pkf file\n");
	printf("--show-pkf <pkf path> show pkf content\n");
	printf("--set-nanan(-n) <nanan path> set nanan path\n");
	printf("--import-root <opk path> import root pkf file\n");
	printf("--version show version\n");
	printf("\n");
	printf("http://www.4dogs.cn\n");
	printf("%s\n\n", XIXI_VERSION);
}

int handle_arguments(int argc, char* argv[]) {
	int opt,show_version, longidx;
	int import_root,show_pkf;
	const char* short_opts = ":p:l:s:v:n:";
	struct option long_opts[] = {
		/*0*/{"make-pkf",1,NULL,'p'},
		/*1*/{"make-license",1,NULL,'l'},
		/*2*/{"sign-pkf",1,NULL,'s'},
		/*3*/{"verify-pkf",1,NULL,'v'},
		/*4*/{"show-pkf",1,&show_pkf,0x2011},
		/*5*/{"version",0,&show_version,0x2013},
		/*6*/{"set-nanan",1,NULL,'n'},
		/*7*/{"import-root",1,&import_root,0x2012},
		{0,0,0,0}
	};

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
			}
			break;
		case 's':
			g_arguments.sign_pkf = 1;
			strcpy(g_arguments.pkf_path, optarg);
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
			strcpy(g_arguments.pkf_path, optarg);
			break;
		case 'n':
			g_arguments.set_nanan = 1;
			strcpy(g_arguments.nanan_path, optarg);
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

int main(int argc, char* argv[]) {
	int err, make_key;
	PPKF pkf;
	uuid_t uu;

	if (argc == 1) {
		usage();
		return 0;
	}

	err = handle_arguments(argc, argv);
	if (err != 0) {
		return 1;
	}

	if (strlen(g_arguments.nanan_path) == 0) {
		strcpy(g_arguments.nanan_path, NANAN_PATH);
	} else {
		pkfSetNanan(g_arguments.nanan_path);
	}

	/* 处理命令行 */
	if (g_arguments.show_version) {
		printf("%s\n", XIXI_VERSION);
	} else if (g_arguments.show_pkf) {
		FILE* fp;
		unsigned char* tmp;
		unsigned long tmpsize;
		fp = fopen(g_arguments.pkf_path, "rb");
		if (!fp) {
			printf("[-] open pkf file:%s error\n", g_arguments.pkf_path);
			return 1;
		}
		
		err = read_file(g_arguments.pkf_path,
						&tmp,
						&tmpsize);
		if (err != 0) {
			fclose(fp);
			printf("[-] read pkf file%s error\n", g_arguments.pkf_path);
			return 1;
		}
		fclose(fp);

		pkf = (PPKF)tmp;
		pkfShow(pkf);
		free(tmp);
	} else if (g_arguments.make_pkf) {
		char private_key_path[256];
		char public_key_path[256];

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
				goto _error;
			}
			fclose(fp);
			printf("\n");
			
			pkfShow(pkf);
			pkfFree(pkf);
		}

	} else if (g_arguments.make_license) {
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
