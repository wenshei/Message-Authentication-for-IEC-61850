#include <chrono>
#include <cstring>
#include <fstream>

#include "Config.h"
#include "Constants.h"
#include "CryptoUtils.h"
#include "Message.h"
#include "wolfssl/wolfcrypt/random.h"

void GenerateNonces(Message* messages, int num_messages, std::chrono::_V2::system_clock::duration* duration) {
#ifdef WRITE_TO_FILE
    std::ofstream nonce_timings;
    nonce_timings.open("nonce_timings.txt", std::ios_base::app);
    nonce_timings << "Duration for " << num_messages << " messages\n";
   // Globals::results << "Nonce generation" << "\n"; 
#endif

    RNG rng;
    wc_InitRng(&rng);

    unsigned char nonce[Constants::kNonceLength];
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < num_messages; i++) {
        // generate nonce for each message
        wc_RNG_GenerateBlock(&rng, nonce, Constants::kNonceLength);
        memcpy(messages[i].nonce_, nonce, Constants::kNonceLength);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    *duration = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);
    
    wc_FreeRng(&rng);

#ifdef WRITE_TO_FILE
    nonce_timings << duration->count() << "\n\n";
    nonce_timings.close();
    //Globals::results << Globals::duration.count() << ",";
#endif
}
