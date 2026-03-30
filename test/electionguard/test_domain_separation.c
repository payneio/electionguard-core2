#include <electionguard/constants.h>
#include <stdio.h>

// Test that all v2.1 domain separation byte constants exist and have correct values
int main() {
    // Test version bytes array
    if (EG_V21_VERSION_BYTES[0] != 0x76) {
        printf("FAIL: EG_V21_VERSION_BYTES[0] != 0x76\n");
        return 1;
    }
    if (EG_V21_VERSION_BYTES[1] != 0x32) {
        printf("FAIL: EG_V21_VERSION_BYTES[1] != 0x32\n");
        return 1;
    }
    if (EG_V21_VERSION_BYTES[2] != 0x2E) {
        printf("FAIL: EG_V21_VERSION_BYTES[2] != 0x2E\n");
        return 1;
    }
    if (EG_V21_VERSION_BYTES[3] != 0x31) {
        printf("FAIL: EG_V21_VERSION_BYTES[3] != 0x31\n");
        return 1;
    }
    if (EG_V21_VERSION_BYTES[4] != 0x2E) {
        printf("FAIL: EG_V21_VERSION_BYTES[4] != 0x2E\n");
        return 1;
    }
    if (EG_V21_VERSION_BYTES[5] != 0x30) {
        printf("FAIL: EG_V21_VERSION_BYTES[5] != 0x30\n");
        return 1;
    }

    // Test domain separation constants
    if (EG_DS_PARAMETER_HASH != 0x00) {
        printf("FAIL: EG_DS_PARAMETER_HASH != 0x00\n");
        return 1;
    }
    if (EG_DS_ELECTION_BASE_HASH != 0x01) {
        printf("FAIL: EG_DS_ELECTION_BASE_HASH != 0x01\n");
        return 1;
    }
    if (EG_DS_KEY_GENERATION_NIZK != 0x10) {
        printf("FAIL: EG_DS_KEY_GENERATION_NIZK != 0x10\n");
        return 1;
    }
    if (EG_DS_SHARE_ENC_KEY != 0x11) {
        printf("FAIL: EG_DS_SHARE_ENC_KEY != 0x11\n");
        return 1;
    }
    if (EG_DS_SHARE_ENC_PROOF != 0x12) {
        printf("FAIL: EG_DS_SHARE_ENC_PROOF != 0x12\n");
        return 1;
    }
    if (EG_DS_GUARDIAN_RECORD_HASH != 0x13) {
        printf("FAIL: EG_DS_GUARDIAN_RECORD_HASH != 0x13\n");
        return 1;
    }
    if (EG_DS_EXTENDED_BASE_HASH != 0x14) {
        printf("FAIL: EG_DS_EXTENDED_BASE_HASH != 0x14\n");
        return 1;
    }
    if (EG_DS_SELECTION_ENC_ID != 0x20) {
        printf("FAIL: EG_DS_SELECTION_ENC_ID != 0x20\n");
        return 1;
    }
    if (EG_DS_ENCRYPTION_NONCE != 0x21) {
        printf("FAIL: EG_DS_ENCRYPTION_NONCE != 0x21\n");
        return 1;
    }
    if (EG_DS_BALLOT_NONCE_ENC_KEY != 0x22) {
        printf("FAIL: EG_DS_BALLOT_NONCE_ENC_KEY != 0x22\n");
        return 1;
    }
    if (EG_DS_BALLOT_NONCE_ENC_PROOF != 0x23) {
        printf("FAIL: EG_DS_BALLOT_NONCE_ENC_PROOF != 0x23\n");
        return 1;
    }
    if (EG_DS_RANGE_PROOF != 0x24) {
        printf("FAIL: EG_DS_RANGE_PROOF != 0x24\n");
        return 1;
    }
    if (EG_DS_CONTEST_DATA_NONCE != 0x25) {
        printf("FAIL: EG_DS_CONTEST_DATA_NONCE != 0x25\n");
        return 1;
    }
    if (EG_DS_CONTEST_DATA_ENC_KEY != 0x26) {
        printf("FAIL: EG_DS_CONTEST_DATA_ENC_KEY != 0x26\n");
        return 1;
    }
    if (EG_DS_CONTEST_DATA_ENC_PROOF != 0x27) {
        printf("FAIL: EG_DS_CONTEST_DATA_ENC_PROOF != 0x27\n");
        return 1;
    }
    if (EG_DS_CONTEST_HASH != 0x28) {
        printf("FAIL: EG_DS_CONTEST_HASH != 0x28\n");
        return 1;
    }
    if (EG_DS_CONFIRMATION_CODE != 0x29) {
        printf("FAIL: EG_DS_CONFIRMATION_CODE != 0x29\n");
        return 1;
    }
    if (EG_DS_DEVICE_INFO_HASH != 0x2A) {
        printf("FAIL: EG_DS_DEVICE_INFO_HASH != 0x2A\n");
        return 1;
    }
    if (EG_DS_CHAIN_CLOSING != 0x2B) {
        printf("FAIL: EG_DS_CHAIN_CLOSING != 0x2B\n");
        return 1;
    }
    if (EG_DS_TALLY_DECRYPT_COMMIT != 0x30) {
        printf("FAIL: EG_DS_TALLY_DECRYPT_COMMIT != 0x30\n");
        return 1;
    }
    if (EG_DS_TALLY_DECRYPT_PROOF != 0x31) {
        printf("FAIL: EG_DS_TALLY_DECRYPT_PROOF != 0x31\n");
        return 1;
    }
    if (EG_DS_CONTEST_DECRYPT_COMMIT != 0x32) {
        printf("FAIL: EG_DS_CONTEST_DECRYPT_COMMIT != 0x32\n");
        return 1;
    }
    if (EG_DS_CONTEST_DECRYPT_PROOF != 0x33) {
        printf("FAIL: EG_DS_CONTEST_DECRYPT_PROOF != 0x33\n");
        return 1;
    }
    if (EG_DS_PREENC_SELECTION_HASH != 0x40) {
        printf("FAIL: EG_DS_PREENC_SELECTION_HASH != 0x40\n");
        return 1;
    }
    if (EG_DS_PREENC_CONTEST_HASH != 0x41) {
        printf("FAIL: EG_DS_PREENC_CONTEST_HASH != 0x41\n");
        return 1;
    }
    if (EG_DS_PREENC_CONFIRM_CODE != 0x42) {
        printf("FAIL: EG_DS_PREENC_CONFIRM_CODE != 0x42\n");
        return 1;
    }
    if (EG_DS_PREENC_DEVICE_INFO != 0x43) {
        printf("FAIL: EG_DS_PREENC_DEVICE_INFO != 0x43\n");
        return 1;
    }
    if (EG_DS_PREENC_CHAIN_CLOSING != 0x44) {
        printf("FAIL: EG_DS_PREENC_CHAIN_CLOSING != 0x44\n");
        return 1;
    }
    if (EG_DS_PREENC_NONCE_DERIV != 0x45) {
        printf("FAIL: EG_DS_PREENC_NONCE_DERIV != 0x45\n");
        return 1;
    }

    printf("PASS: All domain separation constants present and correct\n");
    return 0;
}
