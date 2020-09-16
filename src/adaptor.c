#include <omp.h>
#include "adaptor.h"
#include "zkproof.h"

// TODO: Clear merkelize from adaptor and zkproof.
void get_challenges_adaptor(const unsigned char *hash, uint32_t *challenges_index, uint8_t *challenges_sign) {
	unsigned char tmp_hash[SEED_BYTES];
	memcpy(tmp_hash, hash, SEED_BYTES);

	// slow hash function
	for (int i = 0; i < HASHES; i++) {
		HASH(tmp_hash, SEED_BYTES, tmp_hash);
	}

	// generate pseudorandomness
	EXPAND(tmp_hash, SEED_BYTES, (unsigned char *) challenges_index, sizeof(uint32_t)*ROUNDS);

	// set sign bit and zero out higher order bits
	for (int i = 0; i < ROUNDS; i++) {
		challenges_sign[i] = (challenges_index[i] >> PK_TREE_DEPTH) & 1;
		challenges_index[i] &= (((uint16_t) 1) << PK_TREE_DEPTH) - 1;
	}
}

void uint_print(uint const *x)
{
    for (size_t i = 8*LIMBS-1; i < 8*LIMBS; --i)
        printf("%02hhx", i[(unsigned char *) x->c]);
}

void fp_print(fp const *x)
{
    uint y;
    fp_dec(&y, x);
    uint_print(&y);
}

void csifish_presign(const unsigned char *sk, const unsigned char *m, uint64_t mlen, const public_key Ey, adaptor_sig_t presig) {
	init_classgroup();

	// hash the message
	unsigned char m_hash[HASH_BYTES];
	HASH(m, mlen, m_hash);

	// pick random seeds
	unsigned char seeds[SEED_BYTES*ROUNDS];
	RAND_bytes(seeds,SEED_BYTES*ROUNDS);

	// compute curves
	mpz_t r[ROUNDS];
	uint curves[ROUNDS] = {{{0}}};
	uint* presig_curves = (uint*) presig->curves;

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for (int k = 0; k < ROUNDS; k++) {
		private_key priv;

		// sample mod class number and convert to vector
		mpz_init(r[k]);
		sample_mod_cn_with_seed(seeds + k*SEED_BYTES, r[k]);
		mod_cn_2_vec(r[k], priv.e);

		// compute group actions
		public_key out, out_hat;
		action(&out_hat, &base, &priv);
    action(&out, &Ey, &priv);

		// convert to uint64_t's
		fp_dec(&curves[k], &out.A);
    fp_dec(&presig_curves[k], &out.A);

    public_key statement[] = { base, out_hat, Ey, out };
    csifish_zk_prover(statement, 2*L_j, r[k], presig->proofs[k]);
	}

	#ifdef MERKLEIZE_PK
		// copy curves to signature
		memcpy(SIG_CURVES(sig), (unsigned char *) curves, sizeof(uint[ROUNDS]));
	#endif

	// hash curves
	unsigned char curve_hash[HASH_BYTES];
	HASH((unsigned char *) curves, sizeof(uint[ROUNDS]), curve_hash);

	// compute master hash
	unsigned char in_buf[2*HASH_BYTES], master_hash[HASH_BYTES];
	memcpy(in_buf, m_hash, HASH_BYTES);
	memcpy(in_buf + HASH_BYTES, curve_hash, HASH_BYTES);
	HASH(in_buf, 2*HASH_BYTES, master_hash);

	#ifndef MERKLEIZE_PK
		// copy hash to signature
		memcpy(presig->sig, master_hash, HASH_BYTES);
	#endif

	// get challenges
	uint32_t challenges_index[ROUNDS];
	uint8_t challenges_sign[ROUNDS];
	get_challenges_adaptor(master_hash, challenges_index, challenges_sign);

	// generate seeds
	unsigned char *sk_seeds = malloc(SEED_BYTES*PKS);
	EXPAND(sk, SEED_BYTES, sk_seeds, SEED_BYTES*PKS);

	// generate secrets mod p
	unsigned char *indices = calloc(1, PKS);
	(void) indices;
	mpz_t s[ROUNDS];

	for (unsigned i = 0; i < ROUNDS; i++) {
		indices[challenges_index[i]] = 1;
		mpz_init(s[i]);
		sample_mod_cn_with_seed(sk_seeds + challenges_index[i]*SEED_BYTES, s[i]);

		if (challenges_sign[i]) {
			mpz_mul_si(s[i], s[i], -1);
		}
		mpz_sub(r[i], s[i], r[i]);
		mpz_fdiv_r(r[i], r[i], cn);

		// silly trick to force export to have 33 bytes
		mpz_add(r[i], r[i], cn);

		mpz_export(presig->sig + HASH_BYTES + 33*i, NULL, 1, 1, 1, 0, r[i]);

		mpz_clear(s[i]);
		mpz_clear(r[i]);
	}

	#ifdef MERKLEIZE_PK
		// release the necessary nodes of merkle tree
		uint16_t nodes_released;
		release_nodes(SK_TREE(sk), SEED_BYTES, PK_TREE_DEPTH, indices, SIG_TREE_FILLING(sig) , &nodes_released);	
	
		// update signature length
		(*sig_len) = (SIG_TREE_FILLING(0) + nodes_released*SEED_BYTES);
	#endif

	clear_classgroup();
	free(indices);
	free(sk_seeds);
}

#ifdef MERKLEIZE_PK

int csifish_preverify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const public_key Ey, const adaptor_sig_t presig) {
	init_classgroup();

	// hash the message
	unsigned char m_hash[HASH_BYTES];
	HASH(m,mlen,m_hash);

	// hash curves
	uint* curves = (uint*) SIG_CURVES(sig);
	unsigned char curve_hash[HASH_BYTES];
	HASH((unsigned char *) curves, sizeof(uint[ROUNDS]), curve_hash);

	// compute master hash
	unsigned char in_buf[2*HASH_BYTES], master_hash[HASH_BYTES];
	memcpy(in_buf,m_hash,HASH_BYTES);
	memcpy(in_buf + HASH_BYTES, curve_hash, HASH_BYTES);
	HASH(in_buf,2*HASH_BYTES, master_hash);

	// get challenges
	uint32_t challenges_index[ROUNDS];
	uint8_t challenges_sign[ROUNDS];
	get_challenges_adaptor(master_hash,challenges_index,challenges_sign);


	fp minus_one;
	fp_sub3(&minus_one, &fp_0, &fp_1);

	uint *pkcurves = malloc(sizeof(uint[PKS])); 
	unsigned char *indices = calloc(1,PKS);

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for (int i = 0; i < ROUNDS; i++) {
		// encode starting point
		public_key start,end;
		fp_enc(&(start.A), &curves[i]);

		// decode path
		mpz_t x;
		mpz_init(x);
		private_key path;
		mpz_import(x,33,1,1,1,0,SIG_RESPONSES(sig)+33*i);
		mpz_sub(x,x,cn);
		mod_cn_2_vec(x,path.e);
		mpz_clear(x);

		// perform action
		action(&end,&start,&path);

		if (challenges_sign[i]) {
			fp_mul2(&end.A,&minus_one);
		}

		// decode endpoint
		uint pkcurve;
		fp_dec(&pkcurve,&end.A);	

		// put endpoint in pkcurves, or compare to earlier found curve
		if (indices[challenges_index[i]] == 0) {
			pkcurves[challenges_index[i]] = pkcurve;
		} else if (memcmp(&pkcurves[challenges_index[i]],&pkcurve,sizeof(uint))) {
			// curve not equal to earlier found curve! reject signature
			clear_classgroup();
			free(indices);
			free(pkcurves);
			return -1;
		}
		indices[challenges_index[i]] = 1;
	}

	clear_classgroup();

	// reconstruct root of merkle tree
	unsigned char root[SEED_BYTES];
	int nodes = ( sig_len - SIG_TREE_FILLING(0))/SEED_BYTES;
	hash_up(pkcurves, indices,SIG_TREE_FILLING(sig),nodes,root,pk+SEED_BYTES);

	free(indices);
	free(pkcurves);

	// compare root with pk
	if (memcmp(root,pk,SEED_BYTES)) {
		return -1;
	}

	return 1;
}

#else

int csifish_preverify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const public_key Ey, const adaptor_sig_t presig) {
	init_classgroup();

	// hash the message
	unsigned char m_hash[HASH_BYTES];
	HASH(m, mlen, m_hash);

	// get challenges
	uint32_t challenges_index[ROUNDS];
	uint8_t  challenges_sign[ROUNDS];
	get_challenges_adaptor(presig->sig, challenges_index, challenges_sign);

	fp minus_one;
	fp_sub3(&minus_one, &fp_0, &fp_1);

	uint  curves[ROUNDS];
	uint* presig_curves = (uint*) presig->curves;
	uint* pkcurves = (uint*) PK_CURVES(pk);

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for (unsigned i = 0; i < ROUNDS; i++) {
		// encode starting point
		public_key pk_ci, hat_Ei, Ei;
		fp_enc(&(pk_ci.A), &pkcurves[challenges_index[i]]);
    fp_enc(&(Ei.A), &presig_curves[i]);
    memcpy(&curves[i], &presig_curves[i], sizeof(uint));

		if (challenges_sign[i]) {
			fp_mul2(&pk_ci.A, &minus_one);
		}

		// decode path
		mpz_t x;
		mpz_init(x);
		private_key path;

		mpz_import(x, 33, 1, 1, 1, 0, presig->sig + HASH_BYTES + 33*i);
		mpz_sub(x, x, cn);
		mod_cn_2_vec(x, path.e);
		mpz_clear(x);

		// flip vector
		for (int j = 0; j < NUM_PRIMES; j++) {
			path.e[j] = -path.e[j];
		}

		// perform action
		action(&hat_Ei, &pk_ci, &path);

    public_key statement[] = { base, hat_Ei, Ey, Ei };
    if (csifish_zk_verifier(statement, 2*L_j, presig->proofs[i]) != 1) {
      fprintf(stderr, "Error: ZK proof (%u) verification failed.\n", i);
      exit(1);
    }
	}

	clear_classgroup();

	// hash curves
	unsigned char curve_hash[HASH_BYTES];
	HASH((unsigned char *) curves, sizeof(uint[ROUNDS]), curve_hash);

	// compute master hash
	unsigned char in_buf[2*HASH_BYTES], master_hash[HASH_BYTES];
	memcpy(in_buf, m_hash, HASH_BYTES);
	memcpy(in_buf + HASH_BYTES, curve_hash, HASH_BYTES);
	HASH(in_buf, 2*HASH_BYTES, master_hash);

	// compare master_hash with signature_hash
	if (memcmp(master_hash, presig->sig, HASH_BYTES) != 0) {
		return -1;
	}
	return 1;
}

int csifish_ext(const adaptor_sig_t presig, const unsigned char *sig, const public_key Ey, const zk_proof_t piy, mpz_t y) {
  init_classgroup();

	mpz_t r, hat_r;
  mpz_init(r);
  mpz_init(hat_r);

  mpz_import(hat_r, 33, 1, 1, 1, 0, presig->sig + HASH_BYTES);
  mpz_sub(hat_r, hat_r, cn);
  mpz_import(r, 33, 1, 1, 1, 0, sig + HASH_BYTES);
  mpz_sub(r, r, cn);

  mpz_sub(y, hat_r, r);

  mpz_clear(r);
  mpz_clear(hat_r);

  private_key y_prime;
  public_key Ey_prime;

  mod_cn_2_vec(y, y_prime.e);
	action(&Ey_prime, &base, &y_prime);
  if (memcmp(&Ey, &Ey_prime, sizeof(public_key)) != 0) {
    fprintf(stderr, "Error: invalid witness\n");
    clear_classgroup();
    return -1;
  }

  public_key statement[] = { base, Ey };
  if (csifish_zk_verifier(statement, L_j, piy) != 1) {
    fprintf(stderr, "Error: ZK proof (ext) verification failed.\n");
    clear_classgroup();
    return -1;
  }

  return 1;
	clear_classgroup();
}

void csifish_adapt(const adaptor_sig_t presig, const mpz_t y, unsigned char *sig) {
  init_classgroup();

	mpz_t r[ROUNDS], hat_r[ROUNDS];
  memcpy(sig, presig->sig, HASH_BYTES);

	#ifdef PARALLELIZE
	#pragma omp parallel for
	#endif
	for (unsigned i = 0; i < ROUNDS; i++) {
		// decode path
		mpz_init(r[i]);
    mpz_init(hat_r[i]);

		mpz_import(hat_r[i], 33, 1, 1, 1, 0, presig->sig + HASH_BYTES + 33*i);
		mpz_sub(hat_r[i], hat_r[i], cn);

    mpz_sub(r[i], hat_r[i], y);
    mpz_fdiv_r(r[i], r[i], cn);

		// silly trick to force export to have 33 bytes
		mpz_add(r[i], r[i], cn);

		mpz_export(sig + HASH_BYTES + 33*i, NULL, 1, 1, 1, 0, r[i]);

    mpz_clear(r[i]);
		mpz_clear(hat_r[i]);
	}

  if (memcmp(sig, presig->sig, HASH_BYTES) != 0) {
    fprintf(stderr, "Error: invalid memory block!\n");
  }

	clear_classgroup();
}

#endif
