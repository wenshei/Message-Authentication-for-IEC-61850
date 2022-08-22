#include <iostream>
#include <vector>
#include <fstream>

#include "CryptoUtils.h"
#include "Message.h"
#include "HuffTree.h"
#include "ProveVerify.cpp"
#include "HuffmanCode.h"
#include "GenerateMessages.cpp"
#include "GenerateNonces.cpp"
#include "Config.h"

int main(int argc, char **argv) {
    std::vector<int>num_messages_vect = {16, 64, 256, 1024};
    std::pair<double, double> avg_duration;
    std::chrono::_V2::system_clock::duration duration_nonces, duration_build_tree;
    double avg_sig_size;

#ifdef WRITE_TO_FILE
    std::ofstream results("results.txt", std::ios_base::app);
#endif

    for (auto num_messages : num_messages_vect){
        std::cout << "Number of messages: " << num_messages << "\t";
        Message messages[num_messages] = {};

        //Generate random messages according to the number of message
        GenerateMessages(messages, num_messages);

        /****** Precomputation ******/
        GenerateNonces(messages, num_messages, &duration_nonces);
        HuffmanCode *hct = new HuffmanCode(messages, num_messages, &duration_build_tree); // build huffman tree
        
        HuffmanNode *theRoot = hct->getFinalTree()->getRoot(); // get the final root for prove and verify

        /****** Prove and Verify ******/
        int fails = ProveVerifyMultipleMessages(theRoot, hct->map_, messages, num_messages, &avg_duration, &avg_sig_size);
        std::cout << "Fails: " << fails << std::endl;

        delete(hct);

    #ifdef WRITE_TO_FILE
        // Globals::results << "--------------------------\n";
        // Globals::results << "Timings for " << Globals::num_messages << " messages \n";
        // Globals::results << "--------------------------\n";
        // results << "Nonce generation" << "\n"; 
        results << duration_nonces.count() << ",";
        // results << "Build Tree" << "\n";
        results << duration_build_tree.count() << ",";
        //results << "Prove" << "\n";
        results << avg_duration.first << "," ;
        //results << "Verify" << "\n";
        results << avg_duration.second << ",";
        // results << "Signature size" << "\n";
        results << avg_sig_size << ",";
    #endif
    }

#ifdef WRITE_TO_FILE
    results << "\n";
    results.close();
#endif
    return 0;
}
