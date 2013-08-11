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

#define NANAN_PATH                 "./nanan"
typedef struct _ARGUMENTS {
	int show_version;
	
	int make_pkf;
	int make_license;
	int sign_pkf;
	int set_nanan;
	int import_opk;

	char nanan_path[128];
	char pkf_path[128];
	char owner_private_key_path[128];
} ARGUMENTS, *PARGUMENTS;

ARGUMENTS g_arguments = {
	0,                /* show version */
	0,                /* make pkf */
	0,                /* make license */
    0,                /* sign pkf */
	0,                /* set nanan path */
    0,                /* import opk */
	{0},              /* nanan path */
	{0},              /* pkf path */
    {0}               /* owner private key path */
};

void usage() {
	printf("xixi [options]\n");
	printf("--make-pkf(-p) <pkf path>\n");
	printf("--make-license(-l) <pkf path>\n");
	printf("--sign-pkf(-s) <pkf path>\n");
	printf("--set-nanan(-n) <nanan path>\n");
	printf("--import-opk <opk path>\n");
	printf("\n");
	printf("http://www.4dogs.cn\n");
	printf("%s\n\n", XIXI_VERSION);
}

int handle_arguments(int argc, char* argv[]) {
	int opt,show_version, longidx;
	int import_opk;
	const char* short_opts = ":p:l:s:";
	struct option long_opts[] = {
		/*0*/{"make-pkf",1,NULL,'p'},
		/*1*/{"make-license",1,NULL,'l'},
		/*2*/{"sign-pkf",1,NULL,'s'},
		/*3*/{"version",0,&show_version,0x2013},
		/*4*/{"set-nanan",1,NULL,'n'},
		/*5*/{"import-opk",1,&import_opk,0x2012},
		{0,0,0,0}
	};

	while ((opt = getopt_long(argc, argv, short_opts, 
							  long_opts, &longidx)) != -1) {
		switch (opt) {
		case 0:
			if ((show_version == 0x2013) && (longidx == 3)) {
				g_arguments.show_version = 1;
			} else if ((import_opt == 0x2012) && (longidx == 5)) {
				g_arguments.import_opk = 1;
				strcpy(g_arguments.owner_private_key_path,
					   optarg);
			}
			break;
		case 's':
			g_arguments.sign_pkf = 1;
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
		case 's':
			
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
	printf("hash:");
	s = gets(buffer);
	hash_id = atoi(buffer);
	printf("sign:");
	s = gets(buffer);
	sign_id = atoi(buffer);
	printf("prng:");
	s = gets(buffer);
	prng_id = atoi(buffer);
	printf("end time(year):");
	s = gets(buffer);
	end_data = atoi(buffer);
	printf("make key:");
	s = gets(buffer);
	if (strlen(buffer)) *make_key = 1;
	else *make_key = 0;
	//printf("crypt private key:");
	//s = gets(buffer);
	//if (strlen(buffer)) {
	printf("crypt private key:");
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

	if (g_arguments.make_pkf) {
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

		if (strlen(g_arguments.nanan_path) == 0)
			strcpy(g_arguments.nanan_path, NANAN_PATH);

		pkf = pkfMake(pkf, 
					  make_key, 
					  public_key_path,
					  private_key_path,
					  g_arguments.nanan_path);

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
			if ((err = fwrite((unsigned char*)pkf
							  , 1, total, fp)) != total) {
				printf("[-] write pkf error\n");
				goto _error;
			}
			fclose(fp);
			printf("\n");
			
			pkfShow(pkf);
			pkfFree(pkf);
		}

	} else if (g_arguments.make_license) {
	} else if (g_arguments.sign_pkf) {
		PPKF pkf;
		FILE* fp;
		int err;
		if (!g_arguments.import_opk) {
			printf("[-] not import private key\n");
			return 1;
		}

		pkf = pkfSign(g_arguments.pkf_path, 
					  g_arguments.owner_private_key_path);
		if (!pkf) {
			printf("[-] sign pkf error\n");
			return 1;
		}
		
		fp = fopen(g_arguments.okf_path, "wb");
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

		pkfShow(pkf);

		fclose(fp);
		pkfFree(pkf);
	}

	

	return 0;

 _error:
	if (pkf) pkfFree(pkf);
	return 1;
}
