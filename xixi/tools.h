static int delete_file(char* file) {
	char buffer[1024];
	
	sprintf(buffer, "rm -f %s", file);
	system(buffer);

	return 0;
}

static int get_file_size(FILE* fp) {
	int total;
	
	fseek(fp, 0, SEEK_END);
	total = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return total;
}

static int read_file_ex(char* file,
						int read_size,
						int offset,
						int flag,
						unsigned char** value,
						unsigned long* value_size) {
	FILE* fp;
	int err, filesize;

	fp = fopen(file, "rb");
	if (!fp) {
		return -1;
	}

	filesize = get_file_size(fp);

	(*value) = (unsigned char*)malloc(filesize+0x10);
	if (!(*value)) {
		fclose(fp);
	}
	if (read_size == 0)
		*value_size = filesize;
	else
		*value_size = read_size;
	
	fseek(fp, offset, flag);

	err = fread(*value, 1, *value_size, fp);
	if (err != *value_size) {
		free(*value);
		fclose(fp);
		return 1;
	}

	fclose(fp);
	return 0;
}						

static int read_file(char* file,
					 unsigned char** value,
					 unsigned long* value_size) {
	return read_file_ex(file, 0, 0, SEEK_SET, value, value_size);
}

static int write_file(char* file,
					  unsigned char* value,
					  unsigned long value_size) {
	FILE* fp;
	int err;

	fp = fopen(file, "wb");
	if (!fp) return 1;

	err = fwrite(value, 1, value_size, fp);
	if (err != value_size) {
		fclose(fp);
		return 1;
	}

	fflush(fp);
	fclose(fp);

	return 0;
}

static int hash_file(char* nanan_path,
					 char* file, 
					 int hash_id,
					 unsigned char** value,
					 unsigned long* value_size) {
	int err;
	char buffer[1024] = {0};
	char tmpfile[256] = {0};

	err = 0;

	srand(0);
	sprintf(tmpfile, ".hash_%d", rand());

	sprintf(buffer, "%s --silent -3 %d -h -o %s %s",
			nanan_path, hash_id, tmpfile, file);
	system(buffer);

	err = read_file(tmpfile, value, value_size);
	
	delete_file(tmpfile);

	return err;
}

static int hash_string(char* nanan_path,
					   char* data,
					   int hash_id,
					   unsigned char** value,
					   unsigned long* value_size) {
	char buffer[128];
	char tmpfile[256];
	int err;

	srand(0);
	sprintf(tmpfile, ".hash_%d", rand());

	memset(buffer, 0, sizeof(buffer));
	sprintf(buffer, "echo %s | %s --silent -3 2 -h -o %s",
			data,
			nanan_path,
			tmpfile);
	system(buffer);

	/* 读取HASH值 */
	err = read_file(tmpfile, value, value_size);
	if (err != 0)
		return 1;

	delete_file(tmpfile);
	
	return 0;
}

static int crypt_file(char* nanan_path,
					  char* file,
					  int crypt_id,
					  int hash_id,
					  int encrypt,
					  char* password,
					  unsigned char** value,
					  unsigned long* value_size) {

	int err;
	char buffer[1024] = {0};
	char tmpfile[256] = {0};

	err = 0;

	srand(0);

	if (encrypt) {
		sprintf(tmpfile, ".encrypt_%d", rand());

		sprintf(buffer, 
				"%s --silent -1 %d -3 %d -4 0 -5 3 -e %s -o %s %s", 
				nanan_path,
				crypt_id,
				hash_id,
				password,
				tmpfile,
				file);
	} else {
		sprintf(tmpfile, ".decrypt_%d", rand());

		sprintf(buffer, 
				"%s --silent -1 %d -3 %d -4 0 -5 3 -d %s -o %s %s", 
				nanan_path,
				crypt_id,
				hash_id,
				password,
				tmpfile,
				file);
	}
	system(buffer);

	err = read_file(tmpfile, value, value_size);

	delete_file(tmpfile);
	return err;
}

static int sign_file(char* nanan_path,
					 char* file, 
					 int sign_id,
					 int hash_id,
					 int prng_id,
					 char* private_file,
					 unsigned char** value,
					 unsigned long* value_size) {
	int err;
	char buffer[1024] = {0};
	char tmpfile[256] = {0};

	err = 0;

	srand(0);
	sprintf(tmpfile, ".sign_%d", rand());
	
	sprintf(buffer,
			"%s --silent -2 %d -3 %d -4 %d -s --import-private-key %s -o %s %s",
			nanan_path,
			sign_id,
			hash_id,
			prng_id,
			private_file,
			tmpfile,
			file);
	system(buffer);

	err = read_file(tmpfile, value, value_size);

	delete_file(tmpfile);
	return 0;
}

static int verify_file(char* nanan_path,
					   char* file, 
					   int sign_id,
					   int hash_id,
					   int prng_id,
					   char* public_file,
					   char* signdata_file,
					   unsigned char* result) {
	int err;
	char buffer[1024] = {0};
	char tmpfile[256] = {0};
	unsigned char* value;
	unsigned long value_size;

	srand(0);
	sprintf(tmpfile, ".verify_%d", rand());
	
	sprintf(buffer,
			"%s -2 %d -3 %d -4 %d -v --import-public-key %s --import-sign %s %s > %s",
			nanan_path,
			sign_id,
			hash_id,
			prng_id,
			public_file,
			signdata_file,
			file,
			tmpfile);
	system(buffer);

	err = read_file(tmpfile, &value, &value_size);
	if (memcmp(value, "[+]", 3) == 0)
		*result = 1;
	else
		*result = 0;

	delete_file(tmpfile);
	free(value);

	return 0;
}
