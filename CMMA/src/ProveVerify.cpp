#include <iostream>
#include <vector>
#include <cstring>
#include <string>
#include <map>
#include <chrono>
#include <fstream>

#include "CryptoUtils.h"
#include "HuffmanNode.h"
#include "Constants.h"
#include "ProofNode.h"
#include "Config.h"
#include "wolfssl/wolfcrypt/random.h"

void Prove(std::map<std::string, std::string> hashmap, unsigned char *trueMsg, HuffmanNode *root, unsigned char *nonce, std::vector<ProofNode> *proof, std::chrono::_V2::system_clock::duration* duration) {
    std::string msg_str(reinterpret_cast<char const *>(trueMsg), Constants::kMaxMsgLength);
    // find true message in map to get address
    std::map<std::string, std::string>::iterator itr = hashmap.find(msg_str); 

    if (itr == hashmap.end()) {
        std::cout << "Message not found in map" << std::endl;
        return;
    }

    std::string address = itr->second;
    HuffmanNode *temp = root; 

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < address.size(); i++) {
        // if address is 1, left node is the proof node
        if (address[i] == '1') {
            // create a new proof node and store it in the vector
            ProofNode proof_node = {{0}, 0};
            memcpy(proof_node.hash_, temp->left_->hash_, Constants::kHashLength);
            proof->push_back(proof_node);

            // assign the right node as temp node
            temp = temp->right_;
        }

        // if address is 0, right node is the proof node
        else {
            // create a new proof node and store it in the vector
            ProofNode proof_node = {{0}, 1};
            memcpy(proof_node.hash_, temp->right_->hash_, Constants::kHashLength);
            proof->push_back(proof_node);
          
            // assign the left node as temp node
            temp = temp->left_;
        }
    }
    auto stop = std::chrono::high_resolution_clock::now();
    *duration = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);

    memcpy(nonce, temp->nonce_, Constants::kNonceLength);
}

bool Verify(unsigned char *trueMsg, unsigned char *nonce, std::vector<ProofNode> *proof, unsigned char *stored_hash, std::chrono::_V2::system_clock::duration* duration) {   
    RNG rng; 
    wc_InitRng(&rng);

    /***** Preparation for SHA256 input *****/
    unsigned char HMAC_hash[Constants::kHashLength];
    unsigned char HMAC_nonce_1[Constants::kRandomKey];
    wc_RNG_GenerateBlock(&rng, HMAC_nonce_1, Constants::kRandomKey);

    unsigned char HMAC_nonce_2[Constants::kRandomKey];
    wc_RNG_GenerateBlock(&rng, HMAC_nonce_2, Constants::kRandomKey);

    unsigned char random_hash[Constants::kHashLength];
    unsigned char random_1[Constants::kRandomKey];
    wc_RNG_GenerateBlock(&rng, random_1, Constants::kRandomKey);

    unsigned char verify_hash[Constants::kHashLength];

    auto start = std::chrono::high_resolution_clock::now();
    /****** 2 HMAC *****/
    CryptoUtils::DoSha256(stored_hash, Constants::kHashLength, HMAC_nonce_1, Constants::kRandomKey, HMAC_hash);
    CryptoUtils::DoSha256(HMAC_hash, Constants::kHashLength, HMAC_nonce_2, Constants::kRandomKey, HMAC_hash);
    
    /****** 2 random hash *****/
    CryptoUtils::DoSha256(random_1, Constants::kRandomKey, nullptr, 0, random_hash);
    CryptoUtils::DoSha256(random_hash, Constants::kHashLength, nullptr, 0, random_hash);

    /****** Hash of the true message node *****/
    CryptoUtils::DoSha256(trueMsg, Constants::kMaxMsgLength, nonce, Constants::kNonceLength, verify_hash);

    // iterate from the end of vector
    for (int i = proof->size() - 1; i >= 0; i--) {
        ProofNode temp_proof_node = proof->at(i);

        // if the proof node is right -> H(verify_hash, proof_node_hash)
        if (temp_proof_node.isHashLocationRight_) {
            CryptoUtils::DoSha256(verify_hash, Constants::kHashLength, temp_proof_node.hash_, Constants::kHashLength, verify_hash);
        }

        // if the proof node is left -> H(proof_node_hash, verify_hash)
        else {
            CryptoUtils::DoSha256(temp_proof_node.hash_, Constants::kHashLength, verify_hash, Constants::kHashLength, verify_hash);
        }
    }
    auto stop = std::chrono::high_resolution_clock::now();
    *duration = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);
    
    wc_FreeRng(&rng);

    // check if the calculated hash and the stored hash is equal
    bool res = !(memcmp(stored_hash, verify_hash, Constants::kHashLength));
    return res;
}

int ProveVerifyMultipleMessages(HuffmanNode* root, std::map<std::string, std::string> map_, Message* messages, int num_messages, std::pair<double, double>* avg_duration, double* avg_sig_size) {
#ifdef WRITE_TO_FILE
    std::ofstream prove_timings;
    std::ofstream verify_timings;
    std::ofstream sig_size;
    
    prove_timings.open("prove_timings.txt", std::ios_base::app); //append to the txt file
    prove_timings << "Duration" << "," << "Weight" << "\n";

    verify_timings.open("verify_timings.txt", std::ios_base::app);
    verify_timings << "Duration" << "," << "Weight" << "\n";
    
    sig_size.open("sig_size.txt", std::ios_base::app); 
    sig_size << "Signature size" << "," << "Weight" << "\n";
#endif

    double total_prove_time = 0;
    double total_verify_time = 0;
    double total_sig_size = 0;
    double total_weight = 0;
    int fails = 0;
    unsigned char trueMsg[Constants::kMaxMsgLength] = {}; // true message to verify
    bool res; 
    std::chrono::_V2::system_clock::duration duration; 

    // perform sign and verify for each messages
    for (int i = 0; i < num_messages; i++)
    {
        memcpy(trueMsg, messages[i].content_, Constants::kMaxMsgLength);

        std::vector<ProofNode> proof;
        unsigned char nonce_prove[Constants::kNonceLength];

        /****** Prove function (generate signature) ******/
        Prove(map_, trueMsg, root, nonce_prove, &proof, &duration);

    #ifdef WRITE_TO_FILE
        prove_timings << duration.count() << "," << messages[i].weight_ << "\n";
    #endif
        total_prove_time += duration.count() * messages[i].weight_;

        /****** Verify function ******/
        res = Verify(trueMsg, nonce_prove, &proof, root->hash_, &duration);
        if(!res) {
            // std::cout << "Verification failed" << std::endl;
            fails ++;
        }

    #ifdef WRITE_TO_FILE
        verify_timings << duration.count() << "," << messages[i].weight_ << "\n";
    #endif
        total_verify_time += duration.count() * messages[i].weight_;

        // calculate the size of signature
        int size_of_sig = 0;
        for (auto it : proof)
        {
            size_of_sig += sizeof(it);
        }
        size_of_sig += sizeof(nonce_prove);

    #ifdef WRITE_TO_FILE
        sig_size << size_of_sig * 8 << "," << messages[i].weight_ << "\n";
    #endif

        total_sig_size += size_of_sig * 8 * messages[i].weight_;
        total_weight += messages[i].weight_;
    }

    // calculate the weighted average duration for prove and verify
    avg_duration->first = total_prove_time/total_weight;
    avg_duration->second = total_verify_time/total_weight;
    *avg_sig_size = total_sig_size/total_weight;

#ifdef WRITE_TO_FILE
    prove_timings << avg_duration->first << "\n\n";
    prove_timings.close();
    verify_timings << avg_duration->second << "\n\n";
    verify_timings.close();
    sig_size << *avg_sig_size << "\n\n";
    sig_size.close();
#endif

    return fails;
}
