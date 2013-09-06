static void show_sign(PPKF pkf) {
	unsigned char* sign;
	unsigned long sign_size;

	sign = get_sign(pkf);
	if (sign) {
		sign_size = pkf->issuer.sign_size;
		show_key(sign, sign_size);
	}
}

static void show_issuer(PPKF pkf) {
	PPKF_ISSUER issuer;

	issuer = &(pkf->issuer);
	printf("ISSUER XID = "); 
	show_xid(issuer->pkf_id);
	printf("ISSUER NAME = %s\n", issuer->name);
	printf("SIGN SIZE = %d\n", issuer->sign_size);
	show_sign(pkf);
}

static void show_property(PPKF pkf) {
	unsigned int property;
	unsigned char* key;
	PPKF_PRIVATE_KEY_SECURITY security;

	property = pkf->property;

	if (property & PKF_PROP_PUBLIC) {
		printf("PUBLIC KEY SIZE = %d\n", 
			   pkf->public_key_size);
		key = get_public_key(pkf);
		show_key(key, pkf->public_key_size);
	}

	if (property & PKF_PROP_PRIVATE) {
		printf("PRIVATE KEY SIZE = %d\n", 
			   pkf->private_key_size);
		key = get_private_key(pkf);
		show_key(key, pkf->private_key_size);
	}

	if (property & PKF_PROP_DECRYPT_PRIVATE) {
		int i;
		security = 
			(PPKF_PRIVATE_KEY_SECURITY)get_crypt_private_key_struct(pkf);
		printf("CRYPT PRIVATE KEY ALGORITHM = %s\n", 
			   show_crypt_algorithm(security->crypt_id));
		printf("CRYPT PRIVATE KEY PASSWORD SHA1 = ");
		for (i = 0; i < 20; i++)
			printf("%02x", pkf->password_hash[i]);
		printf("\n");
	}

	if (property & PKF_PROP_ROOT) {
		printf("PKF TYPE = ROOT\n");
	} else {
		show_issuer(pkf);
	}	
}

static void show_pkf(PPKF pkf) {
	int root;
	char buffer[64];
	printf("PKF ID = ");
	show_xid(pkf->pkf_id);
	printf("EMAIL = %s\n", pkf->email);
	printf("ORGANIZATION = %s\n", pkf->organization);

	printf("BEGIN TIME = %s\n", ctime((time_t*)&(pkf->begin_time)));
	printf("END TIME = %s\n", ctime((time_t*)&(pkf->end_time)));

	printf("HASH ALGORITHM = %s\n", 
		   show_hash_algorithm(pkf->sign_support.hash_id));
	printf("SIGN ALGORITHM = %s\n", 
		   show_sign_algorithm(pkf->sign_support.sign_id));
	printf("PRNG ALGORITHM = %s\n", 
		   show_prng_algorithm(pkf->sign_support.prng_id));
 
	show_property(pkf);
}
