#include "electionguard/guardian.hpp"

#include "../log.hpp"
#include "variant_cast.hpp"

#include <memory>
#include <vector>

extern "C" {
#include "electionguard/guardian.h"
}

using electionguard::ElementModP;
using electionguard::GuardianKeySet;
using electionguard::Log;

using std::unique_ptr;
using std::vector;

#pragma region GuardianKeySet

EG_API eg_electionguard_status_t eg_guardian_key_set_generate(uint64_t in_guardian_index,
                                                               uint64_t in_quorum,
                                                               eg_guardian_key_set_t **out_handle)
{
    try {
        auto keySet = GuardianKeySet::generate(in_guardian_index, in_quorum);
        *out_handle = AS_TYPE(eg_guardian_key_set_t, keySet.release());
        return ELECTIONGUARD_STATUS_SUCCESS;
    } catch (const std::exception &e) {
        Log::error(__func__, e);
        return ELECTIONGUARD_STATUS_ERROR_BAD_ALLOC;
    }
}

EG_API eg_electionguard_status_t eg_guardian_key_set_free(eg_guardian_key_set_t *handle)
{
    if (handle == nullptr) {
        return ELECTIONGUARD_STATUS_ERROR_INVALID_ARGUMENT;
    }
    delete AS_TYPE(GuardianKeySet, handle); // NOLINT(cppcoreguidelines-owning-memory)
    handle = nullptr;
    return ELECTIONGUARD_STATUS_SUCCESS;
}

EG_API eg_electionguard_status_t eg_guardian_key_set_get_vote_public_key(
  eg_guardian_key_set_t *handle, eg_element_mod_p_t **out_ref)
{
    auto *pointer = AS_TYPE(GuardianKeySet, handle)->getVotePublicKey();
    *out_ref = AS_TYPE(eg_element_mod_p_t, pointer);
    return ELECTIONGUARD_STATUS_SUCCESS;
}

EG_API eg_electionguard_status_t eg_guardian_key_set_get_data_public_key(
  eg_guardian_key_set_t *handle, eg_element_mod_p_t **out_ref)
{
    auto *pointer = AS_TYPE(GuardianKeySet, handle)->getDataPublicKey();
    *out_ref = AS_TYPE(eg_element_mod_p_t, pointer);
    return ELECTIONGUARD_STATUS_SUCCESS;
}

EG_API eg_electionguard_status_t eg_guardian_key_set_get_communication_public_key(
  eg_guardian_key_set_t *handle, eg_element_mod_p_t **out_ref)
{
    auto *pointer = AS_TYPE(GuardianKeySet, handle)->getCommunicationPublicKey();
    *out_ref = AS_TYPE(eg_element_mod_p_t, pointer);
    return ELECTIONGUARD_STATUS_SUCCESS;
}

EG_API eg_electionguard_status_t eg_guardian_key_set_compute_joint_vote_key(
  eg_guardian_key_set_t **in_guardians, uint64_t in_count, eg_element_mod_p_t **out_joint_key)
{
    try {
        vector<const GuardianKeySet *> guardians;
        guardians.reserve(in_count);
        for (uint64_t i = 0; i < in_count; ++i) {
            guardians.push_back(AS_TYPE(GuardianKeySet, in_guardians[i]));
        }
        auto result = GuardianKeySet::computeJointVoteKey(guardians);
        *out_joint_key = AS_TYPE(eg_element_mod_p_t, result.release());
        return ELECTIONGUARD_STATUS_SUCCESS;
    } catch (const std::exception &e) {
        Log::error(__func__, e);
        return ELECTIONGUARD_STATUS_ERROR_BAD_ALLOC;
    }
}

EG_API eg_electionguard_status_t eg_guardian_key_set_compute_joint_data_key(
  eg_guardian_key_set_t **in_guardians, uint64_t in_count, eg_element_mod_p_t **out_joint_key)
{
    try {
        vector<const GuardianKeySet *> guardians;
        guardians.reserve(in_count);
        for (uint64_t i = 0; i < in_count; ++i) {
            guardians.push_back(AS_TYPE(GuardianKeySet, in_guardians[i]));
        }
        auto result = GuardianKeySet::computeJointDataKey(guardians);
        *out_joint_key = AS_TYPE(eg_element_mod_p_t, result.release());
        return ELECTIONGUARD_STATUS_SUCCESS;
    } catch (const std::exception &e) {
        Log::error(__func__, e);
        return ELECTIONGUARD_STATUS_ERROR_BAD_ALLOC;
    }
}

#pragma endregion
