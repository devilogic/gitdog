#define DEF_SIGN_ID                0
#define DEF_CRYPT_ID               6
#define DEF_HASH_ID                2
#define DEF_PRNG_ID                0
typedef struct _ARGUMENTS {
	/* [pkf] */
	int make_pkf;
	int sign_pkf;
	int verify_pkf;
	int show_pkf;

	/* [xlicense] */
	int make_license;
	int sign_license;
	int verify_license;
	int show_license;

	/* [import data] */
	int import_parents_pkf;                 /* 用于对PKF进行签名以及验证 */
	int import_user_pkf;                    /* 用于生成执照 */
	int import_owner_pkf;                   /* 用于签名以及验证执照 */
	int import_private_key_password;

	/* [xfile] */
	int encrypt_file;
	int decrypt_file;
	int add_license_to_file;
	int del_license_to_file;
	int set_license_pool;
	int set_target_file;

	/* [select algorithm] */
	int crypt_id;
	int sign_id;
	int hash_id;
	int prng_id;

	/* [misc] */
	int set_nanan;
	int show_version;

	/* 一些数据 */
	char nanan_path[128];                        /* 南南路径 */

	union {
		char pkf_path[128];                          /* 目标PKF的路径 */
		char target_path[128];
	};

	union {
		char owner_pkf_path[128];                /* owner的pkf路径 */
		char parents_pkf_path[128];              /* parents的pkf路径 */
	};
	
	union {
		char license_path[128];
		char license_pool_path[128];
	};

	char private_key_password[32];
} ARGUMENTS, *PARGUMENTS;

static ARGUMENTS g_arguments = {0};

static void init_arguments(PARGUMENTS arg) {
	memset(arg, 0, sizeof(ARGUMENTS));
	arg->crypt_id = DEF_CRYPT_ID;
	arg->sign_id = DEF_SIGN_ID;
	arg->hash_id = DEF_HASH_ID;
	arg->prng_id = DEF_PRNG_ID;
}

static int handle_arguments(int argc, char* argv[]) {
	int opt,longidx;
	int make_pkf,sign_pkf,verify_pkf,show_pkf,
		make_license,sign_license,verify_license,show_license,
		import_parents_pkf,import_user_pkf,import_owner_pkf,import_private_key_password,
		encrypt_file,decrypt_file,
		add_license_to_file,del_license_to_file,
		set_license_pool,set_target_file,
		set_nanan,show_version;
	const char* short_opts = "1:2:3:4:";
	struct option long_opts[] = {
		/*0*/{"make-pkf",1,&make_pkf,0x2013},
		/*1*/{"sign-pkf",1,&sign_pkf,0x2012},
		/*2*/{"verify-pkf",1,&verify_pkf,0x2011},
		/*3*/{"show-pkf",1,&show_pkf,0x2010},
		/*4*/{"make-license",1,&make_license,0x2009},
		/*5*/{"sign-license",1,&sign_license,0x2008},
		/*6*/{"verify-license",1,&verify_license,0x2007},
		/*7*/{"show-license",1,&show_license,0x2006},
		/*8*/{"import-parents-pkf",1,&import_parents_pkf,0x2005},
		/*9*/{"import-user-pkf",1,&import_user_pkf,0x2004},
		/*10*/{"import-owner-pkf",1,&import_owner_pkf,0x2003},
		/*11*/{"import-private-key-password",1,&import_private_key_password,0x2002},
		/*12*/{"encrypt-file",1,&encrypt_file,0x2001},
		/*13*/{"decrypt-file",1,&decrypt_file,0x2000},
		/*14*/{"add-license-to-file",1,&add_license_to_file,0x1999},
		/*15*/{"del-license-to-file",1,&del_license_to_file,0x1998},
		/*16*/{"set-license-pool",1,&set_license_pool,0x1997},
		/*17*/{"set-target-file",1,&set_target_file,0x1996},
		/*18*/{"set-nanan",1,&set_nanan,0x1995},
		/*19*/{"version",0,&show_version,0x1994},
		/*20*/{"select-crypt",1,NULL,'1'},	    /* 选择加密算法 */
		/*21*/{"select-sign",1,NULL,'2'},		/* 选择签名算法 */
		/*22*/{"select-hash",1,NULL,'3'},		/* 选择哈希算法 */
		/*23*/{"select-prng",1,NULL,'4'},		/* 选择随机算法 */
		{0,0,0,0}
	};

	/* 初始化参数结构 */
	init_arguments(&g_arguments);

	while ((opt = getopt_long(argc, argv, short_opts, 
							  long_opts, &longidx)) != -1) {
		switch (opt) {
		case 0:
			if ((longidx == 0) && (make_pkf == 0x2013)) {
				g_arguments.make_pkf = 1;
				strcpy(g_arguments.pkf_path, optarg);
			} else if ((longidx == 1) && (sign_pkf == 0x2012)) {
				g_arguments.sign_pkf = 1;
				strcpy(g_arguments.pkf_path, optarg);
			} else if ((longidx == 2) && (verify_pkf == 0x2011)) {
				g_arguments.verify_pkf = 1;
				strcpy(g_arguments.pkf_path, optarg);
			} else if ((longidx == 3) && (show_pkf == 0x2010)) {
				g_arguments.show_pkf = 1;
				strcpy(g_arguments.pkf_path, optarg);
			} else if ((longidx == 4) && (make_license == 0x2009)) {
				g_arguments.make_license = 1;
				strcpy(g_arguments.license_path, optarg);
			} else if ((longidx == 5) && (sign_license == 0x2008)) {
				g_arguments.sign_license = 1;
				strcpy(g_arguments.license_path, optarg);
			} else if ((longidx == 6) && (verify_license == 0x2007)) {
				g_arguments.verify_license = 1;
				strcpy(g_arguments.license_path, optarg);
			} else if ((longidx == 7) && (show_license == 0x2006)) {
				g_arguments.show_license = 1;
				strcpy(g_arguments.license_path, optarg);
			} else if ((longidx == 8) && (import_parents_pkf == 0x2005)) {
				g_arguments.import_parents_pkf = 1;
				strcpy(g_arguments.parents_pkf_path, optarg);
			} else if ((longidx == 9) && (import_user_pkf == 0x2004)) {
				g_arguments.import_user_pkf = 1;
				strcpy(g_arguments.pkf_path, optarg);
			} else if ((longidx == 10) && (import_owner_pkf == 0x2003)) {
				g_arguments.import_owner_pkf = 1;
				strcpy(g_arguments.owner_pkf_path, optarg);
			} else if ((longidx == 11) && (import_private_key_password == 0x2002)) {
				g_arguments.import_private_key_password = 1;
				strcpy(g_arguments.private_key_password, optarg);
			} else if ((longidx == 12) && (encrypt_file == 0x2001)) {
				g_arguments.encrypt_file = 1;
				strcpy(g_arguments.target_path, optarg);
			} else if ((longidx == 13) && (decrypt_file == 0x2000)) {
				g_arguments.decrypt_file = 1;
				strcpy(g_arguments.target_path, optarg);
			} else if ((longidx == 14) && (add_license_to_file == 0x1999)) {
				g_arguments.add_license_to_file = 1;
				strcpy(g_arguments.license_path, optarg);
			} else if ((longidx == 15) && (del_license_to_file == 0x1998)) {
				g_arguments.del_license_to_file = 1;
				strcpy(g_arguments.license_path, optarg);
			} else if ((longidx == 16) && (set_license_pool == 0x1997)) {
				g_arguments.set_license_pool = 1;
				strcpy(g_arguments.license_pool_path, optarg);
			} else if ((longidx == 17) && (set_target_file == 0x1996)) {
				g_arguments.set_target_file = 1;
				strcpy(g_arguments.target_path, optarg);
			} else if ((longidx == 18) && (set_nanan == 0x1995)) {
				g_arguments.set_nanan = 1;
				strcpy(g_arguments.nanan_path, optarg);
			} else if ((longidx == 19) && (show_version == 0x1994)) {
				g_arguments.show_version = 1;
			}
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

static void usage() {
	printf("xixi [options]\n");
	printf("[pkf]\n");
	printf("--make-pkf <pkf path> make pkf file\n");
	printf("--sign-pkf <pkf path> sign pkf file\n");
	printf("--verify-pkf <pkf path> verify pkf file\n");
	printf("--show-pkf <pkf path> show pkf content\n");
	printf("\n");
	printf("[xlicense]\n");
	printf("--make-license <license path> make xlicense\n");
	printf("--sign-license <license path> sign xlicense\n");
	printf("--verify-license <license path> verify xlicense\n");
	printf("--show-license <license path> show xlicense\n");
	printf("\n");
	printf("[import data]\n");
	printf("--import-parents-pkf <parents pkf path> import parents pkf file\n");
	printf("--import-user-pkf <pkf path> import owner pkf\n");
	printf("--import-owner-pkf <pkf path> import owner pkf\n");
	printf("--import-private-key-password <password> the password of pkf private key\n");
	printf("\n");
	printf("[xfile]\n");
	printf("--encrypt-file <file path> encrypt file\n");
	printf("--decrypt-file <file path> decrypt file\n");
	printf("--add-license-to-file <license path> add license to file\n");
	printf("--del-license-to-file <license path> del license to file\n");
	printf("--set-license-pool <path> set xlicense directory\n");
	printf("--set-target-file <file path> set target file\n");
	printf("\n");
	printf("[misc]\n");
	printf("--set-nanan <nanan path> set nanan path\n");
	printf("--version show version\n");
	printf("\n");
	printf("select algorithm---\n");
	printf("--select-crypt(-1) <crypt id> select crypt algorithm\n");
	printf("--select-sign(-2) <sign id> select sign algorithm\n");
	printf("--select-hash(-3) <hash id> select hash algorithm\n");
	printf("--select-prng(-4) <prng id>> select random algorithm\n");
	printf("\n");

	printf("http://www.4dogs.cn\n");
	printf("%s\n\n", XIXI_VERSION);
}
