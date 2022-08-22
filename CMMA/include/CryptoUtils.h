#ifndef CRYPTO_ADAPTER_H
#define CRYPTO_ADAPTER_H

namespace CryptoUtils {
    bool DoSha256(const unsigned char* input_1, int input_len_1, const unsigned char* input_2, int input_len_2, unsigned char* output);
}

#endif // CRYPTO_ADAPTER_H
