#ifndef ZKPROOF_H
#define ZKPROOF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csidh.h"
#include "merkletree.h"
#include "stdint.h"
#include "parameters.h"
#include "classgroup.h"
#include "fp.h"

#define PROOF_HASH(proof) (proof)
#define PROOF_RESPONSES(proof) (PROOF_HASH(proof))
#define PROOF_BYTES (PROOF_RESPONSES(0) + 33*ZK_ROUNDS)

typedef struct zk_proof {
  public_key *curves;
  unsigned char *proof;
} zk_proof;

#define zk_proof_new(proof)                                   \
  do {                                                        \
    proof = malloc(sizeof(zk_proof));                         \
    if (proof == NULL) {                                      \
      exit(1);                                                \
    }                                                         \
    (proof)->curves = malloc(2*ZK_ROUNDS*sizeof(public_key)); \
    (proof)->proof = malloc(sizeof(PROOF_BYTES));             \
    if ((proof)->curves == NULL || (proof)->proof == NULL) {  \
      exit(1);                                                \
    }                                                         \
  } while (0)

#define zk_proof_free(proof)                                  \
  do {                                                        \
    free((proof)->curves);                                    \
    free((proof)->proof);                                     \
    free(proof);                                              \
    proof = NULL;                                             \
  } while (0)

void get_binary_challenges(const unsigned char *hash, uint32_t *challenges_index);
void csifish_zk_prover(const public_key* x, const uint64_t xlen, mpz_t s, zk_proof proof);
int csifish_zk_verifier(const public_key* x, const uint64_t xlen, const zk_proof proof);

#endif