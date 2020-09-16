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

void csifish_zk_prover(const public_key* x, const uint64_t xlen, mpz_t s, zk_proof_t proof) {
	// pick random seeds
	unsigned char seeds[SEED_BYTES*ZK_ROUNDS];
	RAND_bytes(seeds, SEED_BYTES*ZK_ROUNDS);

	// compute curves
	mpz_t r[ZK_ROUNDS];
	uint curves[3*L_j*ZK_ROUNDS] = {{{0}}};
	uint* proof_curves = (uint*) proof->curves;

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for (unsigned k = 0; k < ZK_ROUNDS; k++) {
		private_key priv;
		// sample mod class number and convert to vector
		mpz_init(r[k]);
		sample_mod_cn_with_seed(seeds + k*SEED_BYTES, r[k]);
		mod_cn_2_vec(r[k], priv.e);

    for (unsigned j = 0; j < xlen; j += L_j) {
      // compute action
      public_key out;
      action(&out, &x[j], &priv);

      // convert to uint64_t's
      fp_dec(&curves[(k * 3 * L_j) + (j > 0 ? 3 * (j - 1) : 0)], &x[j].A);
      fp_dec(&curves[(k * 3 * L_j) + (j > 0 ? 3 * (j - 1) : 0) + 1], &x[j+1].A);
      fp_dec(&curves[(k * 3 * L_j) + (j > 0 ? 3 * (j - 1) : 0) + 2], &out.A);
			fp_dec(&proof_curves[((k * L_j) + (j > 0 ? j - 1 : 0))], &out.A);
    }
	}

	// hash curves
	unsigned char curve_hash[HASH_BYTES];
	HASH((unsigned char *) curves, sizeof(uint[3*L_j*ZK_ROUNDS]), curve_hash);

	// get challenges
	uint32_t challenges_index[ZK_ROUNDS];
	get_binary_challenges(curve_hash, challenges_index);

	// generate secrets mod p
	mpz_t ss[ZK_ROUNDS];

	for (unsigned i = 0; i < ZK_ROUNDS; i++) {
		mpz_init(ss[i]);
		if (challenges_index[i]) {
			mpz_set(ss[i], s);
		} else {
			mpz_set_si(ss[i], 0);
		}

    mpz_sub(r[i], ss[i], r[i]);
		mpz_fdiv_r(r[i], r[i], cn);

		// silly trick to force export to have 33 bytes
		mpz_add(r[i], r[i], cn);

		mpz_export(proof->sig + 33*i, NULL, 1, 1, 1, 0, r[i]);

		mpz_clear(ss[i]);
		mpz_clear(r[i]);
	}
}

int csifish_zk_verifier(const public_key* x, const uint64_t xlen, const zk_proof_t proof) {
	int fail = 0;

	// get challenges
	uint* proof_curves = (uint*) proof->curves;
	uint curves[3*L_j*ZK_ROUNDS] = {{{0}}};

	for (unsigned k = 0; k < ZK_ROUNDS; k++) {
		for (unsigned j = 0; j < xlen; j += L_j) {
			fp_dec(&curves[(k * 3 * L_j) + (j > 0 ? 3 * (j - 1) : 0)], &x[j].A);
      fp_dec(&curves[(k * 3 * L_j) + (j > 0 ? 3 * (j - 1) : 0) + 1], &x[j+1].A);
      memcpy(&curves[(k * 3 * L_j) + (j > 0 ? 3 * (j - 1) : 0) + 2], &proof_curves[(k * L_j) + (j > 0 ? j - 1 : 0)], sizeof(uint));
		}
	}

	// hash curves
	unsigned char curve_hash[HASH_BYTES];
	HASH((unsigned char *) curves, sizeof(uint[3*L_j*ZK_ROUNDS]), curve_hash);

	// get challenges
	uint32_t challenges_index[ZK_ROUNDS];
	get_binary_challenges(curve_hash, challenges_index);

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for (unsigned i = 0; i < ZK_ROUNDS; i++) {
		if (fail) continue;
		
    // decode path
    mpz_t z;
    mpz_init(z);
    mpz_import(z, 33, 1, 1, 1, 0, proof->sig + 33*i);
    mpz_sub(z, z, cn);

    private_key path;
    mod_cn_2_vec(z, path.e);
    mpz_clear(z);

    // flip vector
    for (int j = 0; j < NUM_PRIMES; j++) {
      path.e[j] = -path.e[j];
    }

    for (unsigned j = 0; j < xlen; j += L_j) {
      // encode starting point
      public_key start, end;
      if (challenges_index[i]) {
        start = x[j+1];
      } else {
        start = x[j];
      }

      // perform action
      action(&end, &start, &path);

			public_key curve_i_j;
			fp_enc(&curve_i_j.A, &proof_curves[(i * L_j) + (j > 0 ? j - 1 : 0)]);

      if (memcmp(&end, &curve_i_j, sizeof(public_key)) != 0) {
        fail = 1;
      }
    }
	}

	if (fail) return -1;
	return 1;
}
