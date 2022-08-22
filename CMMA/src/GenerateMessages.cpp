#include <cmath>
#include <cstring>
#include <iostream>

#include "Constants.h"
#include "Message.h"

void GenerateMessages(Message* messages, int num_messages) {   
    double weight = 0.0;
    unsigned char content[Constants::kMaxMsgLength];
    // pre-generate the contents and weights for each messsage
    for (int i = 0; i < num_messages; i++) {
        // calculate the weight for each message
        weight = 1 / (double(i+1));
        messages[i].weight_ = weight;

        // generate random contents for each message
        unsigned char random[Constants::kMaxMsgLength];
        for (int j = 0; j < Constants::kMaxMsgLength; j++) {
            random[j] = (unsigned char)(rand() % 255 + 1);
        }
        memcpy(messages[i].content_, random, Constants::kMaxMsgLength);
    }
}
