#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "csifish.h"
#include "stdint.h"
#include <time.h>

#define KEYS 1
#define SIGNATURES_PER_KEY 10
#define CLOCK_PRECISION 1E9

static inline
uint64_t rdtsc(void) {
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline 
uint64_t timer(void) {
	struct timespec time;
	clock_gettime(CLOCK_REALTIME, &time);
	return (long long) (time.tv_sec * CLOCK_PRECISION + time.tv_nsec);
}

int main(void) {
	uint64_t start_time, stop_time;
	unsigned char *pk = aligned_alloc(64,PK_BYTES);
	unsigned char *sk = aligned_alloc(64,SK_BYTES);

	printf("pk bytes : %ld\n", (long) PK_BYTES );
	printf("sk bytes : %ld\n", (long) SK_BYTES );

	unsigned char message[1];
	message[0] = 42;
	unsigned char sig[SIG_BYTES+1];
	uint64_t sig_len;

	double keygenTime = 0;
	double signTime = 0;
	double verifyTime = 0;
	uint64_t keygenCycles = 0;
	uint64_t signCycles = 0;
	uint64_t verifyCycles = 0;
	uint64_t sig_size = 0;
	uint64_t sig_size_max = 0;
	uint64_t sig_size_min = 10000000;
	uint64_t t;

	for(int i = 0 ; i < KEYS; i++){
		printf("keygen #%d \n", i);
		start_time = timer();
		t = rdtsc();

		csifish_keygen(pk, sk);
		stop_time = timer();
		keygenCycles += rdtsc() - t;
		keygenTime += 1000. * ((stop_time - start_time) / CLOCK_PRECISION);

		for(int j = 0; j < SIGNATURES_PER_KEY; j++){
			printf("signature #%d for key %d \n", j , i );

			start_time = timer();
			t = rdtsc();
			csifish_sign(sk,message, 1, sig, &sig_len);
			stop_time = timer();
			signCycles += rdtsc() - t;
			signTime += 1000. * ((stop_time - start_time) / CLOCK_PRECISION);
			sig_size += sig_len;

			sig_size_max = (sig_len > sig_size_max ? sig_len : sig_size_max);
			sig_size_min = (sig_len > sig_size_min ? sig_size_min : sig_len);

			sig[sig_len] = 0;

			start_time = timer();
			t = rdtsc();
			int ver = csifish_verify(pk,message,1,sig, sig_len);
			stop_time = timer();
			verifyCycles += rdtsc() - t;
			verifyTime += 1000. * ((stop_time - start_time) / CLOCK_PRECISION);

			if (ver < 0){
				printf("Signature invalid! \n");
			}
		}
	}

	printf("average sig bytes: %ld\n", sig_size / KEYS / SIGNATURES_PER_KEY); 
	printf("maximum sig bytes: %ld\n", sig_size_max); 
	printf("minimum sig bytes: %ld\n\n", sig_size_min); 

	printf("keygen cycles :       %lu \n", keygenCycles / KEYS);
	printf("signing cycles :      %lu \n", signCycles / KEYS / SIGNATURES_PER_KEY);
	printf("verification cycles : %lu \n\n", verifyCycles / KEYS / SIGNATURES_PER_KEY);

	printf("keygen time :       %lf ms \n", keygenTime / KEYS);
	printf("signing time :      %lf ms \n", signTime / KEYS / SIGNATURES_PER_KEY);
	printf("verification time : %lf ms \n", verifyTime / KEYS / SIGNATURES_PER_KEY);

	free(pk);
	free(sk);
	return 0;
}
