BITS?=512

OS_NAME := $(shell uname -s | tr A-Z a-z)

ifeq ($(OS_NAME),darwin)
CC = /usr/local/opt/llvm/bin/clang
OMPFLAG = -I/usr/local/include -I/usr/local/opt/llvm/include -fopenmp
LDFLAG = -L/usr/local/opt/llvm/lib -L/usr/local/lib
else
CC = cc
OMPFLAG = -I/usr/local/include -fopenmp
LDFLAG = -L/usr/local/lib
endif

ifndef UINT_IMPL
	UINT_IMPL=uint.c
	ifneq ("$(wildcard p${BITS}/uint.s)", "")
		UINT_IMPL="$(wildcard p${BITS}/uint.*)"
	endif
endif

ifndef FP_IMPL
	FP_IMPL=fp.c
	ifneq ("$(wildcard p${BITS}/fp.s)", "")
		FP_IMPL="$(wildcard p${BITS}/fp.*)"
	endif
endif

test: csidh.c zkproof.c zkproof.h adaptor.c adaptor.h mont.c classgroup.c reduce.c reduce.h test.c csidh.h mont.h classgroup.h keccaklib merkletree.c merkletree.h
	@${CC} \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VAL},-DBENCH_VAL=${BENCH_VAL}) \
		$(if ${BENCH_ACT},-DBENCH_ACT=${BENCH_ACT}) \
		-I ./ \
		-I p${BITS}/ \
		-I XKCP/bin/generic64/ \
		-L XKCP/bin/generic64/ \
		-std=c11 -pedantic \
		${OMPFLAG} \
		-Wall -Wextra \
		-Wno-unused-parameter \
		-Wno-unused-variable \
		-march=native -O3 \
		p${BITS}/constants.c \
		rng.c \
		${UINT_IMPL} ${FP_IMPL} \
		mont.c \
		csidh.c \
		test.c \
		zkproof.c \
		adaptor.c \
		csifish.c \
		merkletree.c \
		reduce.c \
		classgroup.c \
		-o test -lm -lgmp -lcrypto -lkeccak ${LDFLAG}

keccaklib: 
	(cd XKCP; make generic64/libkeccak.a)

clean:
	@rm -f test

