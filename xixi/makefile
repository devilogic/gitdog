# MAKEFILE for linux GCC
#

# The version
VERSION=1.0

PLATFORM := $(shell uname | sed -e 's/_.*//')

# Compiler and Linker Names
#CC=gcc
#LD=ld

ifndef MAKE
MAKE=make
endif

# ranlib tools
ifndef RANLIB
ifeq ($(PLATFORM), Darwin)
RANLIB=ranlib -c
else
RANLIB=ranlib
endif
endif

# 使用PKF版本1
CFLAGS += -DPKF_VERSION_1

# 开启调试选项
ifdef DEBUG
CFLAGS += -g3
CFLAGS += -lefence -lpthread
endif

ifndef LIBPATH
LIBPATH=../extra
endif
ifndef INCPATH
INCPATH=/usr/include
endif

OBJECTS=pkf.o xlicense.o xcontent.o
SOURCES=pkf.c xlicense.c xcontent.c xixi.c
HEADERS=arguments.h pkf_show.h version.h xixi_tools.h xlicense_tools.h\
	common.h pkf_tools.h xcontent.h xlicense.h\
	pkf.h tools.h xid.h xlicense_show.h

default: application

application: xixi

# 这里有一个链接顺序的问题，必须首先链接.o文件以及.c文件x
# 随后才可以 链接.a文件，否则将找不到一些符号的定义
xixi: $(OBJECTS) $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -L$(LIBPATH) $(OBJECTS) xixi.c $(LIBS) -luuid -o $@

pkf.o: pkf.c pkf.h
	$(CC) $(CFLAGS) -c $< -o $@
xlicense.o: xlicense.c xlicense.h
	$(CC) $(CFLAGS) -c $< -o $@
xcontent.o: xcontent.c xcontent.h
	$(CC) $(CFLAGS) -c $< -o $@

clean_local:
	-rm -f *.o
	-rm xixi

clean:
	-rm -f ./xixi
	-rm -f `find . -type f | grep "[.]o" | xargs`
