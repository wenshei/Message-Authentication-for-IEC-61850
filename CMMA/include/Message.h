#ifndef MESSAGE_H
#define MESSAGE_H

#include "Constants.h"

struct Message {
    double weight_ = 0.0;
    unsigned char content_[Constants::kMaxMsgLength] = {};
    unsigned char nonce_[Constants::kNonceLength] = {};
};

#endif // MESSAGE_H
