#ifndef ADAPTOR_H
#define ADAPTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "classgroup.h"
#include "csidh.h"
#include "fp.h"
#include "merkletree.h"
#include "parameters.h"
#include "zkproof.h"

#define PK_CURVES(pk) (pk)
#define PK_BYTES sizeof(uint[PKS])

#define SK_SEED(sk) (sk)
#define SK_BYTES SEED_BYTES

#define PRESIG_HASH(presig) (presig)
#define PRESIG_RESPONSES(presig) (PRESIG_HASH(presig) + HASH_BYTES)
#define PRESIG_CURVES_BYTES sizeof(uint[ROUNDS])
#define PRESIG_BYTES (33*ROUNDS + PROOF_BYTES*ROUNDS + PRESIG_CURVES_BYTES)

typedef struct {
  unsigned char *sig;
  unsigned char *curves;
  zk_proof_t *proofs;
} adaptor_sig_st;

typedef adaptor_sig_st *adaptor_sig_t;

#define adaptor_sig_new(presig)                               \
  do {                                                        \
    presig = malloc(sizeof(adaptor_sig_st));                  \
    if (presig == NULL) {                                     \
      fprintf(stderr, "Error: could not allocate memory.\n"); \
      exit(1);                                                \
    }                                                         \
    (presig)->sig = malloc(HASH_BYTES + 33*ROUNDS);           \
    (presig)->curves = aligned_alloc(64, PRESIG_CURVES_BYTES);\
    (presig)->proofs = malloc(sizeof(zk_proof_t)*ROUNDS);     \
    if ((presig)->sig == NULL || (presig)->proofs == NULL     \
    ||  (presig)->curves == NULL) {                           \
      fprintf(stderr, "Error: could not allocate memory.\n"); \
      exit(1);                                                \
    }                                                         \
    for (size_t i = 0; i < ROUNDS; i++) {                     \
      zk_proof_new((presig)->proofs[i]);                      \
    }                                                         \
  } while (0)

#define adaptor_sig_free(presig)                              \
  do {                                                        \
    free((presig)->sig);                                      \
    free((presig)->curves);                                   \
    for (size_t i = 0; i < ROUNDS; i++) {                     \
      zk_proof_free((presig)->proofs[i]);                     \
    }                                                         \
    free((presig)->proofs);                                   \
    free(presig);                                             \
    presig = NULL;                                            \
  } while (0)

void get_challenges_adaptor(const unsigned char *hash, uint32_t *challenges_index, uint8_t *challenges_sign);
void csifish_presign(const unsigned char *sk,const unsigned char *m, uint64_t mlen, const public_key Ey, adaptor_sig_t presig);
int csifish_preverify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const public_key Ey, const adaptor_sig_t presig);
int csifish_ext(const adaptor_sig_t presig, const unsigned char *sig, const public_key Ey, const zk_proof_t piy, mpz_t y);
void csifish_adapt(const adaptor_sig_t presig, const mpz_t y, unsigned char *sig);

#endif