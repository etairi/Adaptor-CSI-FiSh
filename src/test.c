#define _POSIX_C_SOURCE 199309L
#include <omp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include "adaptor.h"
#include "csifish.h"

#define KEYS 1
#define SIGNATURES_PER_KEY 5
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
	#ifdef PARALLELIZE
	int nprocs = omp_get_num_procs();
	omp_set_num_threads(nprocs);
	#endif

	unsigned char *pk = aligned_alloc(64, PK_BYTES);
	unsigned char *sk = aligned_alloc(64, SK_BYTES);

	printf("pk bytes : %ld\n", (long) PK_BYTES);
	printf("sk bytes : %ld\n", (long) SK_BYTES);

	unsigned char message[1];
	message[0] = 42;
	
	unsigned char sig[SIG_BYTES+1];
	//uint64_t sig_len;

	adaptor_sig_t presig;
	adaptor_sig_new(presig);

	mpz_t mpz_y;
	mpz_init(mpz_y);

	private_key y;
	public_key Ey;

	zk_proof_t piy;
	zk_proof_new(piy);

	uint64_t start_time, stop_time;
	uint64_t start_cycles, stop_cycles;
	double keygen_time = 0;
	double presign_time = 0;
	double preverify_time = 0;
	double ext_time = 0;
	double adapt_time = 0;
	uint64_t keygen_cycles = 0;
	uint64_t presign_cycles = 0;
	uint64_t preverify_cycles = 0;
	uint64_t ext_cycles = 0;
	uint64_t adapt_cycles = 0;
	//uint64_t sig_size = 0;
	uint64_t sig_size_max = 0;
	uint64_t sig_size_min = 10000000;

	for (int i = 0; i < KEYS; i++) {
		// sample y, ey, and compute proof
		init_classgroup();
		sample_mod_cn(mpz_y);
		mod_cn_2_vec(mpz_y, y.e);
		action(&Ey, &base, &y);

		public_key statement[] = { base, Ey };
		csifish_zk_prover(statement, L_j, mpz_y, piy);
		clear_classgroup();

		printf("keygen #%d\n", i);
		start_time = timer();
		start_cycles = rdtsc();
		csifish_keygen(pk, sk);
		stop_time = timer();
		stop_cycles = rdtsc();
		keygen_cycles += stop_cycles - start_cycles;
		keygen_time += ((stop_time - start_time) / CLOCK_PRECISION);

		for (int j = 0; j < SIGNATURES_PER_KEY; j++) {
			printf("signature #%d for key %d\n", j, i);

			start_time = timer();
			start_cycles = rdtsc();
			csifish_presign(sk, message, 1, Ey, presig);
			stop_time = timer();
			stop_cycles = rdtsc();
			presign_cycles += stop_cycles - start_cycles;
			presign_time += ((stop_time - start_time) / CLOCK_PRECISION);

			// sig_size += sig_len;
			// sig_size_max = (sig_len > sig_size_max ? sig_len : sig_size_max);
			// sig_size_min = (sig_len > sig_size_min ? sig_size_min : sig_len);
			// sig[sig_len] = 0;

			start_time = timer();
			start_cycles = rdtsc();
			int presig_ver = csifish_preverify(pk, message, 1, Ey, presig);
			stop_time = timer();
			stop_cycles = rdtsc();
			preverify_cycles += stop_cycles - start_cycles;
			preverify_time += ((stop_time - start_time) / CLOCK_PRECISION);

			if (presig_ver < 0) {
				fprintf(stderr, "Error: pre-signature invalid!\n");
				goto cleanup;
			}

			sig[SIG_BYTES] = 0;
			start_time = timer();
			start_cycles = rdtsc();
			csifish_adapt(presig, mpz_y, sig);
			stop_time = timer();
			stop_cycles = rdtsc();
			adapt_cycles += stop_cycles - start_cycles;
			adapt_time += ((stop_time - start_time) / CLOCK_PRECISION);

			int sig_ver = csifish_verify(pk, message, 1, sig, SIG_BYTES);
			if (sig_ver < 0) {
				fprintf(stderr, "Error: signature invalid (%d)!\n", sig_ver);
				goto cleanup;
			}

			mpz_t mpz_y_prime;
			mpz_init(mpz_y_prime);
			
			start_time = timer();
			start_cycles = rdtsc();
			int ext_flag = csifish_ext(presig, sig, Ey, piy, mpz_y_prime);
			stop_time = timer();
			stop_cycles = rdtsc();
			ext_cycles += stop_cycles - start_cycles;
			ext_time += ((stop_time - start_time) / CLOCK_PRECISION);

			if (ext_flag < 0) {
				fprintf(stderr, "Error: extraction failed!\n");
				goto cleanup;
			}

			mpz_clear(mpz_y_prime);
		}
	}

	//printf("average sig bytes: %ld\n", (uint64_t) sig_size / KEYS / SIGNATURES_PER_KEY); 
	printf("maximum sig bytes: %ld\n", sig_size_max); 
	printf("minimum sig bytes: %ld\n\n", sig_size_min); 

	printf("keygen cycles :       %lu \n", (uint64_t) keygen_cycles / KEYS);
	printf("signing cycles :      %lu \n", (uint64_t) presign_cycles / KEYS / SIGNATURES_PER_KEY);
	printf("verification cycles : %lu \n\n", (uint64_t) preverify_cycles / KEYS / SIGNATURES_PER_KEY);

	printf("keygen time :       %lf sec \n", keygen_time / KEYS);
	printf("signing time :      %lf sec \n", presign_time / KEYS / SIGNATURES_PER_KEY);
	printf("verification time : %lf sec \n", preverify_time / KEYS / SIGNATURES_PER_KEY);

	cleanup:
	mpz_clear(mpz_y);
	zk_proof_free(piy);
	adaptor_sig_free(presig);
	free(pk);
	free(sk);

	return 0;
}
