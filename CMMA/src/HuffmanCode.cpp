#include <chrono>
#include <queue>
#include <fstream>
#include <stack> 
#include <iostream>

#include "HuffmanCode.h"
#include "Config.h"
#include "Constants.h"
#include "CryptoUtils.h"
#include "wolfssl/wolfcrypt/random.h"

// build hufftree
HuffmanCode::HuffmanCode(Message message[], int num_messages, std::chrono::_V2::system_clock::duration* duration) {
#ifdef WRITE_TO_FILE
    std::ofstream precomputation;
    precomputation.open("precomputation_timings.txt", std::ios_base::app);
    precomputation << "Duration for " << num_messages << " messages\n";
   // Globals::results << "Build Tree" << "\n";
#endif

    RNG rng;
    wc_InitRng(&rng);

    HuffTree *left, *right, *top;
    std::priority_queue<HuffTree *, std::vector<HuffTree *>, compare> minHeap;
    
    auto start = std::chrono::high_resolution_clock::now();
    // create a huffman node for each message and insert into min heap
    for (int i = 0; i < num_messages; ++i) {
        HuffTree* temp = new HuffTree(message[i]);
        minHeap.push(temp); 
    }

    while (minHeap.size() > 1) {
        // Extract the nodes with two minimum freq from min heap 
        left = minHeap.top();
        minHeap.pop();

        right = minHeap.top();
        minHeap.pop();

        // create an internal node with the extracted nodes
        top = new HuffTree(left->getRoot(), right->getRoot(), left->getWeight() + right->getWeight());
        minHeap.push(top);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    *duration = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start); 

    final_ = top;
    // insert the message content and the address of each leaf node into the map
    InsertMap(final_->getRoot()); 

    /***** Preparation for hash input *****/
    unsigned char HMAC_hash[Constants::kHashLength];
    unsigned char HMAC_nonce_1[Constants::kRandomKey];
    wc_RNG_GenerateBlock(&rng, HMAC_nonce_1, Constants::kRandomKey);

    unsigned char HMAC_nonce_2[Constants::kRandomKey];
    wc_RNG_GenerateBlock(&rng, HMAC_nonce_2, Constants::kRandomKey);

    unsigned char random_hash[Constants::kHashLength];
    unsigned char random_1[Constants::kRandomKey];
    wc_RNG_GenerateBlock(&rng, random_1, Constants::kRandomKey);

    start = std::chrono::high_resolution_clock::now();
    /****** 2 HMAC *****/
    CryptoUtils::DoSha256((final_->getRoot())->hash_, Constants::kHashLength, HMAC_nonce_1, Constants::kRandomKey, HMAC_hash);
    CryptoUtils::DoSha256(HMAC_hash, Constants::kHashLength, HMAC_nonce_2, Constants::kRandomKey, HMAC_hash);
    
    /****** 2 random hash *****/
    CryptoUtils::DoSha256(random_1, Constants::kRandomKey, nullptr, 0, random_hash);
    CryptoUtils::DoSha256(random_hash, Constants::kHashLength, nullptr, 0, random_hash);

    stop = std::chrono::high_resolution_clock::now();
    *duration += std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start);
    
    wc_FreeRng(&rng);

#ifdef WRITE_TO_FILE
    precomputation << duration->count() << "\n\n";
    precomputation.close();

    // results << Globals::duration.count() << ",";
#endif
}

// insert the message content and the address of each leaf node into map (iteration)
void HuffmanCode::InsertMap(HuffmanNode *root) {
    // to store the address for right internal node
    std::map<double, std::string> temp_map;
    std::stack<HuffmanNode*> stack_node;
    std::stack<std::string> stack_address;
    HuffmanNode *current = root;
    std::string address, right_address = "";
    bool isRight, lastNode = false;

    // traverse the huffman tree to find the address of each message and insert it into map 
    while (current != NULL || !stack_node.empty()) {
        while (!lastNode && current != NULL) {
            stack_node.push(current);
            if (current->weight_ != root->weight_) {
                if (isRight)
                    address += "1";
                else
                    address += "0";
            }

            if (current->right_ != NULL) {
                right_address = address + "1";
                if(current->right_->msg_[0] != '\0') 
                    stack_address.push(right_address);
                
                else
                    temp_map.insert(std::make_pair(current->right_->weight_, right_address));
            }

            if (current->msg_[0] != '\0') {
                std::string msg(reinterpret_cast<char const *>(current->msg_), Constants::kMaxMsgLength);
                map_.insert(std::make_pair(msg, address));
                address.erase(address.size() - 1);
            }

            current = current->left_;
            isRight = false;
        }

        if (stack_node.empty())
            break;
    
        current = stack_node.top();
        current = current->right_;

        if (current != NULL) {
            isRight = true;
            lastNode = true;
            auto itr = temp_map.find(current->weight_);
            // if it is internal node (can be found in temp map)
            if(itr != temp_map.end()) {
                address = itr->second;
                address.erase(address.size() - 1);
                lastNode = false;
            }
        }

        if (lastNode) {
            right_address = stack_address.top();
            stack_address.pop();
            std::string msg(reinterpret_cast<char const *>(current->msg_), Constants::kMaxMsgLength);
            map_.insert(std::make_pair(msg, right_address));
        }

        // clear temp map when reaches the root node
        if(stack_node.top()->weight_ == root->weight_)
            temp_map.clear();
        stack_node.pop();
    }
}   

HuffTree* HuffmanCode::getFinalTree() {
    return final_;
}
