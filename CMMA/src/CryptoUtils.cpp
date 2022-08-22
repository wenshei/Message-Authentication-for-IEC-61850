#include <iostream>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "CryptoUtils.h"

bool CryptoUtils::DoSha256(const unsigned char* input_1, int input_len_1, const unsigned char* input_2, int input_len_2, unsigned char* output) {
    int res = 0;

    SHA256_CTX sha256;
    res = SHA256_Init(&sha256);
    if (res != 1) {
        return false;
    }

    res = SHA256_Update(&sha256, input_1, input_len_1);
    if (res != 1) {
        return false;
    }

    if (input_len_2 != 0)
        res = SHA256_Update(&sha256, input_2, input_len_2);
        if (res != 1) {
            return false;
        }

    res = SHA256_Final(output, &sha256);
    if (res != 1) {
        return false;
    }
    return true;
}
