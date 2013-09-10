#define NANAN_PATH                 "./nanan"

#if defined(INPUT_CRYPT_ALGORITHM)
static PPKF read_pkf_configure_from_stdin(int* make_key, 
										  int* type,
										  char* public_key_path,
										  char* private_key_path) 
#else
static PPKF read_pkf_configure_from_stdin(int* make_key, 
										  int* type,
										  char* public_key_path,
										  char* private_key_path,
										  int crypt_id,
										  int sign_id,
										  int hash_id,
										  int prng_id)
#endif
{
	int err, c;
	PPKF pkf;

#if defined(INPUT_CRYPT_ALGORITHM)
	int hash_id, sign_id, prng_id, crypt_id;
#endif
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

#if defined(INPUT_CRYPT_ALGORITHM)
	printf("hash algorithm:");
	s = gets(buffer);
	hash_id = atoi(buffer);
	printf("sign algorithm:");
	s = gets(buffer);
	sign_id = atoi(buffer);
	printf("prng algorithm:");
	s = gets(buffer);
	prng_id = atoi(buffer);
#endif

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

	printf("pkf type(0(header) 1(public) 2(private) 3(1&2):");
	s = gets(buffer);
	if (strlen(buffer))
		if (atoi(buffer) >= PKF_PUBLIC_PRIVATE) *type = PKF_PUBLIC_PRIVATE;
		else if (atoi(buffer) <= 0) *type = PKF_ONLY;
		else *type = atoi(buffer);
	else
		*type = PKF_ONLY;

	if (*type != PKF_ONLY) {
		printf("make key?:");
		s = gets(buffer);
		if (strlen(buffer)) *make_key = 1;
		else *make_key = 0;

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
		
		/* 私有密钥的加密 */
		if ((*type == PKF_PRIVATE) || (*type == PKF_PUBLIC_PRIVATE)) {
#if defined(INPUT_CRYPT_ALGORITHM)
			printf("crypt private key algorithm:");
			s = gets(buffer);
			crypt_id = atoi(buffer);
#endif
			printf("password(max 32 character):");
			s = gets(buffer);
			strcpy(password, buffer);
		}
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

static void set_nanan(PARGUMENTS arg) {
	if (strlen(arg->nanan_path) == 0) {
		g_nanan_path = NANAN_PATH;
	} else {
		g_nanan_path = arg->nanan_path;
	}
}

#define check_nanan(nanan_path) exist_file(nanan_path)
