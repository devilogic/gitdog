static int get_owner_pkf_id(char* pkf_file, XID id) {
	PPKF pkf;
	unsigned long pkf_size;
	int err;

	err = 0;

	err = read_file(pkf_file,
					(unsigned char**)&pkf,
					&pkf_size);
	if (err != 0) {
		goto _error;
	}

	memcpy(id, pkf->pkf_id, sizeof(XID));

 _error:
	return err;
}

static unsigned char* get_sign(PXLICENSE xlice) {
	unsigned char* sign;
	unsigned int size;

	if (xlice->property & XLICE_PROP_AUTHED == 0) {
		return NULL;
	}

	size = sizeof(XLICENSE) + sizeof(PKF) + xlice->sign_size;
	if (xlice->file_size < size) {
		return NULL;
	}

	sign = (unsigned char*)xlice + sizeof(XLICENSE) + sizeof(PKF);

	return sign;
}

static PPKF get_pkf(PXLICENSE xlice) {
	PPKF pkf;
	unsigned int size;

	size = sizeof(XLICENSE) + sizeof(PKF);

	if (xlice->file_size < size) {
		return NULL;
	}

	pkf = (PPKF)((unsigned char*)xlice + sizeof(XLICENSE));
	xlice->pkf = pkf;

	return pkf;
}

static int xlice_checksum_file(PXLICENSE xlice) {
	int err;
	unsigned char* sha1;
	unsigned long sha1_size;
	char tmpfile[256] = {0};

	err = 0;

	srand(0);
	sprintf(tmpfile, ".checksum_%d", rand());

	sha1 = (unsigned char*)&(xlice->checksum_start);
	sha1_size = xlice->file_size - ((unsigned char*)xlice - sha1);

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

	memcpy(xlice->checksum, sha1, sha1_size);

	delete_file(tmpfile);
	free(sha1);
	return err;
}

static int xlice_checksum_diff(PXLICENSE xlice, unsigned char* checksum) {
	return memcmp(xlice->checksum, checksum, 20);
}
