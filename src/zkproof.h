#ifndef ZKPROOF_H
#define ZKPROOF_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "classgroup.h"
#include "csidh.h"
#include "fp.h"
#include "merkletree.h"
#include "parameters.h"

#define PROOF_CURVES_BYTES sizeof(uint[L_j*ZK_ROUNDS])
#define PROOF_BYTES (33*ZK_ROUNDS + PROOF_CURVES_BYTES)

typedef struct {
  unsigned char *curves;
  unsigned char *sig;
} zk_proof_st;

typedef zk_proof_st *zk_proof_t;

#define zk_proof_new(proof)                                   \
  do {                                                        \
    proof = malloc(sizeof(zk_proof_st));                      \
    if (proof == NULL) {                                      \
      fprintf(stderr, "Error: could not allocate memory.\n"); \
      exit(1);                                                \
    }                                                         \
    (proof)->curves = aligned_alloc(64, PROOF_CURVES_BYTES);  \
    (proof)->sig = malloc(33*ZK_ROUNDS);                      \
    if ((proof)->curves == NULL || (proof)->sig == NULL) {    \
      fprintf(stderr, "Error: could not allocate memory.\n"); \
      exit(1);                                                \
    }                                                         \
  } while (0)

#define zk_proof_free(proof)                                  \
  do {                                                        \
    free((proof)->curves);                                    \
    free((proof)->sig);                                       \
    free(proof);                                              \
    proof = NULL;                                             \
  } while (0)

void get_binary_challenges(const unsigned char *hash, uint32_t *challenges_index);
void csifish_zk_prover(const public_key* x, const uint64_t xlen, mpz_t s, zk_proof_t proof);
int csifish_zk_verifier(const public_key* x, const uint64_t xlen, const zk_proof_t proof);

#endif