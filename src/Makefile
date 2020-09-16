BITS?=512

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
	@cc \
		$(if ${BENCH_ITS},-DBENCH_ITS=${BENCH_ITS}) \
		$(if ${BENCH_VAL},-DBENCH_VAL=${BENCH_VAL}) \
		$(if ${BENCH_ACT},-DBENCH_ACT=${BENCH_ACT}) \
		-I ./ \
		-I p${BITS}/ \
		-I XKCP/bin/generic64/ \
		-L XKCP/bin/generic64/ \
		-std=c11 -pedantic \
		-Wall -Wextra \
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
		-o test -fopenmp -lm -lgmp -lcrypto -lkeccak

keccaklib: 
	(cd XKCP; make generic64/libkeccak.a)

clean:
	@rm -f test

