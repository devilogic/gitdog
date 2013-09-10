# MAKEFILE for linux GCC
#

# The version
VERSION=1.0

PLATFORM := $(shell uname | sed -e 's/_.*//')

# Compiler and Linker Names
ifdef NDK
AR := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar
SYSROOT := $(NDK_HOME)/platforms/android-8/arch-arm/
CC := $(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-gcc --sysroot=$(SYSROOT)
endif

# Tools
ifndef COPY
	COPY=cp
endif

ifndef RM
	RM=rm
endif

ifndef MAKE
  MAKE=make
endif

# 打包选项
ARFLAGS := cr

# ranlib tools
ifndef NDK
ifndef RANLIB
ifeq ($(PLATFORM), Darwin)
	RANLIB=ranlib -c
else
	RANLIB=ranlib
endif
endif
else
	RANLIB=$(NDK_HOME)/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ranlib
endif

# 头文件目录
CFLAGS += -I./libtomcrypt/src/headers -I./libtommath

# tommath的支持
CFLAGS += -DLTM_DESC

# 开启调试选项
# g3 与 g有什么区别
ifdef DEBUG
	CFLAGS += -g3
	CFLAGS += -DDEBUG
endif

# 是否使用动态地址
ifdef PIC
	CFLAGS += -fpic
endif

# 是否要编译APP
ifdef APP
	CFLAGS += -DAPPLICATION
endif

# 产生不同的版本
ifdef SPACELIMIT
	CFLAGS += -DDWARF 
	CFLAGS += -ULTC_SPRNG -ULTC_RC4 -ULTC_FORTUNA -ULTC_SOBER128
	CFLAGS += -ULTC_TIGER -ULTC_MD2 -ULTC_MD4 -ULTC_MD5\
			-ULTC_SHA224 -ULTC_SHA256 -ULTC_SHA384 -ULTC_SHA512\
			-ULTC_RIPEMD128 -ULTC_RIPEMD160 -ULTC_WHIRLPOOL\
			-ULTC_CHC_HASH
	CFLAGS += -ULTC_BLOWFISH -ULTC_XTEA -ULTC_RC5\
			-ULTC_RC6 -ULTC_SAFERP -ULTC_TWOFISH -ULTC_SAFER\
			-ULTC_RC2 -ULTC_DES -ULTC_CAST5 -ULTC_NOEKEON\
			-ULTC_SKIPJACK -ULTC_KHAZAD -ULTC_ANUBIS
	CFLAGS += -ULTC_ECB_MODE -ULTC_CBC_MODE -ULTC_CFB_MODE\
			-ULTC_F8_MODE -ULTC_LRW_MODE -ULTC_OFB_MODE\
			-ULTC_XTS_MODE
else
	CFLAGS += -DGIANT
endif

ifndef LIBPATH
   LIBPATH=/usr/lib
endif
ifndef INCPATH
   INCPATH=/usr/include
endif

LIBS=./libtomcrypt/libtomcrypt.a ./libtommath/libtommath.a

OBJECTS=crypt.o hash.o sign.o random.o error.o tools.o nanan2.o
SOURCES=crypt.c hash.c sign.c random.c error.c tools.c nanan2.c
HEADERS=crypt.h hash.h sign.h random.h error.h tools.h nanan.h version.h argchk.h

ifdef APP
	OBJECTS += nanan.o
	SOURCES += nanan.c
endif

default: lib

lib: libnanan.a
app: nanan
dll: libnanan.so

# 这里有一个链接顺序的问题，必须首先链接.o文件以及.c文件x
# 随后才可以 链接.a文件，否则将找不到一些符号的定义
nanan: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(MAKE) -C ./libtommath
	$(MAKE) -C ./libtomcrypt
	$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o $@

libnanan.a: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(MAKE) -C ./libtommath
	$(MAKE) -C ./libtomcrypt
	$(AR) $(ARFLAGS) $@ $(OBJECTS)
	$(RANLIB) $@

libnanan.so: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(MAKE) -C ./libtommath
	$(MAKE) -C ./libtomcrypt
	$(CC) -shared $(OBJECTS) $(LIBS) -o $@

crypt.o: crypt.c crypt.h
	$(CC) $(CFLAGS) -c $< -o $@
hash.o: hash.c hash.h
	$(CC) $(CFLAGS) -c $< -o $@
sign.o: sign.c sign.h
	$(CC) $(CFLAGS) -c $< -o $@ 
random.o: random.c random.h
	$(CC) $(CFLAGS) -c $< -o $@
error.o: error.c error.h
	$(CC) $(CFLAGS) -c $< -o $@
tools.o: tools.c tools.h
	$(CC) $(CFLAGS) -c $< -o $@
nanan2.o: nanan2.c nanan.h
	$(CC) $(CFLAGS) -c $< -o $@

ifdef APP
nanan.o: nanan.c nanan.h
	$(CC) $(CFLAGS) -c $< -o $@
endif

test: libnanan.a test.c
	$(CC) $(CFLAGS) test.c $< $(LIBS) -o $@

copy_files:
	$(COPY) ./libnanan.a ../lib
	$(COPY) ./libnanan.so ../lib
	$(COPY) ./libtomcrypt/libtomcrypt.a	../lib
	$(COPY) ./libtommath/libtommath.a ../lib
	$(COPY) ./crypt.h ../include/nanan
	$(COPY) ./sign.h ../include/nanan
	$(COPY) ./hash.h ../include/nanan
	$(COPY) ./random.h ../include/nanan
	$(COPY) ./nanan.h ../include/nanan
	$(COPY) ./libtomcrypt/src/headers/*.h ../include/libtomcrypt
	$(COPY) ./libtommath/*.h ../include/libtommath

install:
	$(COPY) ./libnanan.so /usr/local/lib
	$(COPY) ./crypt.h /usr/local/include/nanan
	$(COPY) ./sign.h /usr/local/include/nanan
	$(COPY) ./hash.h /usr/local/include/nanan
	$(COPY) ./random.h /usr/local/include/nanan
	$(COPY) ./nanan.h /usr/local/include/nanan

uninstall:
	$(RM) -f /usr/local/lib/libnanan.so
	$(RM) -f /usr/local/include/nanan/crypt.h
	$(RM) -f /usr/local/include/nanan/sign.h
	$(RM) -f /usr/local/include/nanan/hash.h
	$(RM) -f /usr/local/include/nanan/random.h
	$(RM) -f /usr/local/include/nanan/nanan.h

clean_local:
	-$(RM) -f *.o
	-$(RM) -f *.a
	-$(RM) -f nanan

clean:
	$(MAKE) clean -C ./libtomcrypt
	$(MAKE) clean -C ./libtommath
	-$(RM) -f `find . -type f | grep "[.]o" | xargs`
	-$(RM) -f `find . -type f | grep "[.]a" | xargs`


