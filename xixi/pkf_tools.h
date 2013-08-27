static int checksum_file(PPKF pkf) {
	int err;
	unsigned char* sha1;
	unsigned long sha1_size;
	char tmpfile[256] = {0};

	err = 0;

	srand(0);
	sprintf(tmpfile, ".checksum_%d", rand());

	sha1 = (unsigned char*)&(pkf->checksum_start);
	sha1_size = pkf->file_size - ((unsigned char*)pkf - sha1);

	err = write_file(tmpfile, sha1, sha1_size);
	if (err != 0) {
		return 1;
	}

	sha1 = NULL;
	sha1_size = 0;
	err = hash_file(g_nanan_path, tmpfile, 2, &sha1, &sha1_size);
	if (err != 0) {
		delete_file(tmpfile);
	}

	memcpy(pkf->checksum, sha1, sha1_size);

	delete_file(tmpfile);
	free(sha1);
	return err;
}

static int checksum_diff(PPKF pfk, unsigned char* checksum) {
	return 0;
}

static unsigned char* get_crypt_private_key_struct(PPKF pkf) {
	unsigned char* p;
	p = (unsigned char*)pkf;

	if (pkf->property & PKF_PROP_DECRYPT_PRIVATE)
		p += sizeof(PKF);
	else return NULL;
	
	return p;
}

static unsigned char* get_private_key(PPKF pkf) {
	unsigned char* p;

	if (pkf->property & PKF_PROP_PRIVATE == 0) {
		return NULL;
	}

	p = get_crypt_private_key_struct(pkf);
	if (p) {
		p += sizeof(PKF_PRIVATE_KEY_SECURITY);
	} else {
		p = (unsigned char*)pkf;
		p += sizeof(PKF);
	}

	return p;
}

static unsigned char* get_public_key(PPKF pkf) {
	unsigned char*p;

	/* 没有公钥直接移动到末尾 */
	if (pkf->property & PKF_PROP_PUBLIC == 0) {
		return NULL;
	}

	p = get_private_key(pkf);
	if (p) {
		p += pkf->private_key_size;
	} else {
		p = (unsigned char*)pkf;
		p += sizeof(PKF);
	}

	return p;
}

#if 0
/* 当时写这段程序，应该是鼻炎烦了， 脑子糊涂 */
static unsigned char* get_issuer(PPKF pkf) {
	unsigned char* public_key;
	public_key = get_public_key(pkf);
	public_key += pkf->public_key_size;
	return public_key;
}
#endif

static unsigned char* get_sign(PPKF pkf) {
	unsigned char* sign;
	
	/* 如果是ROOT证书，则无签名 */
	if ((pkf->property & PKF_PROP_ROOT) || 
		(pkf->property & PKF_PROP_SIGN == 0)) {
		return NULL;
	} else {
		sign = get_public_key(pkf);
		if (sign == NULL) {/* 公钥没有何谈签名 */
			return NULL;
		}

		sign += pkf->public_key_size;
	}

	return sign;
}

