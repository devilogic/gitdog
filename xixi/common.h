extern char* g_nanan_path;

static char* g_hash_algorithm[] = {
	"sha256",
	"tiger",
	"sha1",
	"md5",
	"sha384",
	"sha512",
	"md4",
	"md2",
	"rmd128",
	"rmd160",
	"sha224",
	"whirlpool",
	"chc_hash"
};

static char* g_sign_algorithm[] = {
	"rsa",
	"ecc",
	"dsa",
	"dh"
};

static char* g_prng_algorithm[] = {
	"yarrow",
	"sprng",
	"sober128",
	"fortuna",
	"rc4"
};

static char* g_crypt_algorithm[] = {
	"blowfish",
	"xtea",
	"rc5",
	"rc6",
	"safer+",
	"NULL",
	"aes",
	"twofish",
	"safer-k64",
	"safer-sk64",
	"safer-k128",
	"safer-sk128",
	"rc2",
	"des",
	"3des",
	"cast5",
	"noekeon",
	"skipjack",
	"khazad",
	"anubis"
};

static void show_xid(XID xid) {
	int i;
	for (i = 0; i < 16; i++)
		printf("%02x", xid[i]);
	printf("\n");
	return;
}

static char* show_hash_algorithm(int hash_id) {
	return g_hash_algorithm[hash_id];
}

static char* show_sign_algorithm(int sign_id) {
	return g_sign_algorithm[sign_id];
}

static char* show_prng_algorithm(int prng_id) {
	return g_prng_algorithm[prng_id];
}

static char* show_crypt_algorithm(int crypt_id) {
	return g_crypt_algorithm[crypt_id];
}

static void show_key(unsigned char* key, unsigned int size) {
	unsigned int i;
	for(i = 0; i < size; i++) {
		printf("%02x", key[i]);
	}
	printf("\n");
}
