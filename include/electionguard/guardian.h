/// @file guardian.h
#ifndef __ELECTIONGUARD_CPP_GUARDIAN_H_INCLUDED__
#define __ELECTIONGUARD_CPP_GUARDIAN_H_INCLUDED__

#include "export.h"
#include "group.h"
#include "status.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef GuardianKeySet

struct eg_guardian_key_set_s;
typedef struct eg_guardian_key_set_s eg_guardian_key_set_t;

/**
 * Generate all key material for one guardian.
 *
 * @param[in]  in_guardian_index  Guardian index i (1-based by convention).
 * @param[in]  in_quorum          Threshold k: number of polynomial coefficients.
 * @param[out] out_handle         Caller owns; free with eg_guardian_key_set_free.
 */
EG_API eg_electionguard_status_t eg_guardian_key_set_generate(uint64_t in_guardian_index,
                                                               uint64_t in_quorum,
                                                               eg_guardian_key_set_t **out_handle);

/**
 * Free a GuardianKeySet object previously returned by eg_guardian_key_set_generate.
 */
EG_API eg_electionguard_status_t eg_guardian_key_set_free(eg_guardian_key_set_t *handle);

/**
 * Get the vote public key K_i = g^{s_i} mod p (non-owning reference).
 *
 * @param[out] out_ref  Reference into the key set — not owned by caller; do not free.
 */
EG_API eg_electionguard_status_t
eg_guardian_key_set_get_vote_public_key(eg_guardian_key_set_t *handle,
                                        eg_element_mod_p_t **out_ref);

/**
 * Get the data public key K_hat_i = g^{s_hat_i} mod p (non-owning reference).
 *
 * @param[out] out_ref  Reference into the key set — not owned by caller; do not free.
 */
EG_API eg_electionguard_status_t
eg_guardian_key_set_get_data_public_key(eg_guardian_key_set_t *handle,
                                        eg_element_mod_p_t **out_ref);

/**
 * Get the communication public key kappa_i = g^{zeta_i} mod p (non-owning reference).
 *
 * @param[out] out_ref  Reference into the key set — not owned by caller; do not free.
 */
EG_API eg_electionguard_status_t
eg_guardian_key_set_get_communication_public_key(eg_guardian_key_set_t *handle,
                                                 eg_element_mod_p_t **out_ref);

/**
 * Compute the joint vote public key K = prod(K_i) mod p.
 *
 * @param[in]  in_guardians  Array of guardian key-set pointers.
 * @param[in]  in_count      Number of guardians.
 * @param[out] out_joint_key Caller owns; free with eg_element_mod_p_free.
 */
EG_API eg_electionguard_status_t
eg_guardian_key_set_compute_joint_vote_key(eg_guardian_key_set_t **in_guardians, uint64_t in_count,
                                           eg_element_mod_p_t **out_joint_key);

/**
 * Compute the joint data public key K_hat = prod(K_hat_i) mod p.
 *
 * @param[in]  in_guardians  Array of guardian key-set pointers.
 * @param[in]  in_count      Number of guardians.
 * @param[out] out_joint_key Caller owns; free with eg_element_mod_p_free.
 */
EG_API eg_electionguard_status_t
eg_guardian_key_set_compute_joint_data_key(eg_guardian_key_set_t **in_guardians, uint64_t in_count,
                                           eg_element_mod_p_t **out_joint_key);

#endif /* GuardianKeySet */

#ifdef __cplusplus
}
#endif
#endif /* __ELECTIONGUARD_CPP_GUARDIAN_H_INCLUDED__ */
