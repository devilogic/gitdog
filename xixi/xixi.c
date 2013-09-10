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

char* g_nanan_path = NULL;                      /* 南南的唯一路径 */

#include "arguments.h"
#include "xixi_tools.h"

int main(int argc, char* argv[]) {
	int err;
	PPKF pkf;
	PXLICENSE xlice;
	unsigned long pkf_size, xlice_size;

	if (argc == 1) {
		usage();
		return 0;
	}

	err = handle_arguments(argc, argv);
	if (err != 0) {
		return 1;
	}

	set_nanan(&g_arguments);

	if (check_nanan(g_nanan_path) == 0) {
		printf("[-] nanan not exist\n");
		return 1;
	}

	/* 处理命令行 */
	if (0) {
		/* 无意义 */
	} else if (g_arguments.make_pkf) {
		int make_key;
		int type;
		char private_key_path[256];
		char public_key_path[256];

		err = 0;
		make_key = 0;
#if defined(INPUT_CRYPT_ALGORITHM)
		pkf = read_pkf_configure_from_stdin(&make_key,
											&type,
											public_key_path,
											private_key_path);
#else
		pkf = read_pkf_configure_from_stdin(&make_key,
											&type,
											public_key_path,
											private_key_path,
											g_arguments.crypt_id,
											g_arguments.sign_id,
											g_arguments.hash_id,
											g_arguments.prng_id);
#endif
		if (pkf == NULL) {
			printf("[-] make pkf header error\n");
			return 1;
		}

		pkf = pkfMake(pkf, 
					  make_key, 
					  type,
					  public_key_path,
					  private_key_path);

		if (!pkf) {
			printf("[-] pkf make error\n");
			return 1;
		}

		/* 写入文件 */
		err = write_file(g_arguments.pkf_path,
						 (unsigned char*)pkf,
						 pkf->file_size);
		if (err != 0) {
			printf("[-] write pkf error\n");
			pkfFree(pkf);
			return 1;
		}
		printf("\n");
		pkfShow(pkf);
		pkfFree(pkf);
	} else if (g_arguments.sign_pkf) {
		PKF_ISSUER issuer;
		char private_out_file[256];
		char password[128];
		char* s;
		
		memset(&issuer, 0, sizeof(PKF_ISSUER));

		if (!g_arguments.import_parents_pkf) {
			printf("[-] not import parents pkf\n");
			return 1;
		}

		err = pkfReadIssuer(g_arguments.parents_pkf_path,
							&issuer);
		if (err != 0) {
			printf("[-] read issuer info error\n");
			return 1;
		}
		
		if (g_arguments.import_private_key_password) {
			strcpy(password, g_arguments.private_key_password);
		} else {
			printf("[-] miss private key password\n");
			return 1;
		}
		err = pkfReadPrivateKey(g_arguments.parents_pkf_path,
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

		pkfShow(pkf);
		pkfFree(pkf);
	} else if (g_arguments.verify_pkf) {
		int result;
		char public_out_file[256];

		if (!g_arguments.import_parents_pkf) {
			printf("[-] not import parents pkf\n");
			return 1;
		}

		err = pkfReadPublicKey(g_arguments.parents_pkf_path,
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
			//printf("[+] verify success\n");
		} else {
			printf("[-] verify failed\n");
		}
	} else if (g_arguments.show_pkf) {
		err = read_file(g_arguments.pkf_path,
						(unsigned char**)&pkf,
						&pkf_size);
		if (err != 0) {
			printf("[-] read pkf file%s error\n", g_arguments.pkf_path);
			return 1;
		}

		pkfShow(pkf);
		pkfFree(pkf);
	} else if (g_arguments.make_license) {
		if (!g_arguments.import_user_pkf) {
			printf("[-] not import user pkf\n");
			return 1;
		}
		
		xlice = xliceAlloc(g_arguments.crypt_id);
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

		err = write_file(g_arguments.license_path,
						 (unsigned char*)xlice,
						 xlice->file_size);
		if (err != 0) {
			xliceFree(xlice);
			printf("[-] write xlicense file:%s error\n",
				   g_arguments.license_path);
			return 1;
		}

		xliceShow(xlice);
		xliceFree(xlice);
	} else if (g_arguments.sign_license) {
		char password[32];
		//char owner_private_key_path[256];
		memset(password, 0, 32);

		if (g_arguments.import_owner_pkf == 0) {
			printf("[-] not import owner pkf\n");
			return 1;
		}

		/* 确定文件是否存在 */
		if (exist_file(g_arguments.owner_pkf_path) == 0) {
			printf("[-] owner pkf is not exist\n");
			return 1;
		}

		if (exist_file(g_arguments.license_path) == 0) {
			printf("[-] xlicense file is not exist\n");
			return 1;
		}

		if (g_arguments.import_private_key_password) {
			strcpy(password, g_arguments.private_key_password);
		} else {
			printf("[-] miss private key password\n");
			return 1;
		}

		/*
		err = pkfReadPrivateKey(g_arguments.owner_pkf_path,
								owner_private_key_path,
								password);
		if (err != 0) {
			printf("[-] read private key error\n");
			return 1;
		}
		*/
		err = xliceSignIt(g_arguments.owner_pkf_path,
						  g_arguments.license_path,
						  g_arguments.private_key_password);
		if (err != 0) {
			printf("[-] sign xlicense file:%s error\n",
				   g_arguments.license_path);
			return 1;
		}
	} else if (g_arguments.verify_license) {
		int result;

		if (g_arguments.import_owner_pkf == 0) {
			printf("[-] not import owner pkf\n");
			return 1;
		}

		err = xliceVerify(g_arguments.owner_pkf_path,
						  g_arguments.license_path,
						  &result);
		if (err != 0) {
			printf("[-] verify xlicense file:%s error\n",
				   g_arguments.license_path);
			return 1;
		}
		
		if (result == 0) {
			printf("[-] verify failed\n");
		} else {
			printf("[+] verify success\n");
		}
	} else if (g_arguments.show_license) {
		err = read_file(g_arguments.license_path,
						(unsigned char**)&xlice,
						&xlice_size);
		if (err != 0) {
			printf("[-] read xlicense file%s error\n", g_arguments.license_path);
			return 1;
		}

		xliceSetPKF1(xlice);
		xliceShow(xlice);
		xliceFree(xlice);
	} else if (g_arguments.encrypt_file) {
	} else if (g_arguments.decrypt_file) {
	} else if (g_arguments.add_license_to_file) {
	} else if (g_arguments.del_license_to_file) {
	} else if (g_arguments.show_version) {
		printf("%s\n", XIXI_VERSION);
	}

	return 0;
 _error:
	if (pkf) pkfFree(pkf);
	if (xlice) xliceFree(xlice);
	return err;
}
