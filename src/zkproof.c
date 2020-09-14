#include <omp.h>
#include "zkproof.h"

void get_binary_challenges(const unsigned char *hash, uint32_t *challenges_index) {
	unsigned char tmp_hash[SEED_BYTES];
	memcpy(tmp_hash, hash, SEED_BYTES);

	// slow hash function
	for (int i = 0; i < HASHES; i++) {
		HASH(tmp_hash, SEED_BYTES, tmp_hash);
	}

	// generate pseudorandomness
	EXPAND(tmp_hash, SEED_BYTES, (unsigned char *) challenges_index, sizeof(uint32_t)*ZK_ROUNDS);

	// set sign bit and zero out higher order bits
	for (int i = 0; i < ZK_ROUNDS; i++) {
		challenges_index[i] &= (((uint16_t) 1) << 1) - 1;
	}
}

void csifish_zk_prover(const public_key* x, const uint64_t xlen, mpz_t s, zk_proof proof) {
	init_classgroup();

	// pick random seeds
	unsigned char seeds[SEED_BYTES*ROUNDS];
	RAND_bytes(seeds,SEED_BYTES*ROUNDS);

	// compute curves
	mpz_t r[ZK_ROUNDS];
	uint curves[3*ZK_ROUNDS] = {{{0}}};

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for (int k = 0; k < ZK_ROUNDS; k++) {
		private_key priv;
		// sample mod class number and convert to vector
		mpz_init(r[k]);
		sample_mod_cn_with_seed(seeds + k*SEED_BYTES, r[k]);
		mod_cn_2_vec(r[k], priv.e);

    for (int j = 0; j < xlen; j += 2) {
      // compute action
      public_key out;
      action(&out, &x[j], &priv);

      // convert to uint64_t's
      fp_dec(&curves[(k * 3)], &x[j].A);
      fp_dec(&curves[(k * 3) + 1], &x[j+1].A);
      fp_dec(&curves[(k * 3) + 2], &out.A);

      memcpy(proof.curves + (((k * 2) + (j > 0 ? j - 1 : 0)) * sizeof(public_key)), &out, sizeof(public_key));
    }
	}

	// hash curves
	unsigned char curve_hash[HASH_BYTES];
	HASH((unsigned char *) curves, sizeof(uint[3*ZK_ROUNDS]), curve_hash);

	// get challenges
	uint32_t challenges_index[ZK_ROUNDS];
	get_binary_challenges(curve_hash, challenges_index);

	// generate secrets mod p
	mpz_t ss[ZK_ROUNDS];

	for (int i = 0; i < ZK_ROUNDS; i++) {
		mpz_init(ss[i]);
		if (challenges_index[i]) {
			mpz_mul_si(ss[i], s, -1);
      mpz_sub(r[i], ss[i], r[i]);
		}
		
		mpz_fdiv_r(r[i], r[i], cn);

		// silly trick to force export to have 33 bytes
		mpz_add(r[i], r[i], cn);

		mpz_export(PROOF_RESPONSES(proof.proof) + 33*i, NULL, 1, 1, 1, 0, r[i]);

		mpz_clear(ss[i]);
		mpz_clear(r[i]);
	}

	clear_classgroup();
}

int csifish_zk_verifier(const public_key* x, const uint64_t xlen, const zk_proof proof) {
	init_classgroup();

	// get challenges
	uint32_t challenges_index[ZK_ROUNDS];
	get_binary_challenges(PROOF_HASH(proof.proof), challenges_index);

	uint curves[ZK_ROUNDS];

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for(int i = 0; i < ZK_ROUNDS; i++) {
    // decode path
    mpz_t z;
    mpz_init(z);
    mpz_import(z, 33, 1, 1, 1, 0, SIG_RESPONSES(proof.proof) + 33*i);
    mpz_sub(z, z, cn);

    private_key path;
    mod_cn_2_vec(z, path.e);
    mpz_clear(z);

    // flip vector
    for(int j = 0; j < NUM_PRIMES; j++) {
      path.e[j] = -path.e[j];
    }

    for (int j = 0; j < xlen; j += 2) {
      // encode starting point
      public_key start, end;
      if (challenges_index[i]) {
        start = x[j+1];
      } else {
        start = x[j];
      }

      // perform action
      action(&end, &start, &path);

      if (memcmp(&end, &proof.curves[(i * 2) + (j > 0 ? j - 1 : 0)], sizeof(public_key))) {
        return -1;
      }
    }
	}

	clear_classgroup();
	return 1;
}
