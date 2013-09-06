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

	memcpy(id, pkf->id, sizeof(XID));

 _error:
	return err;
}

static unsigned char* get_sign(PXLICENSE xlice) {
	unsigned char* sign;

	if (xlice->property & XLICE_PROP_AUTHED == 0) {
		return NULL;
	}

	sign = (unsigned char*)xlice + sizeof(XLICENSE);

	return sign;
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
