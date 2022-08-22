#include <cstring>

#include "HuffmanNode.h"
#include "CryptoUtils.h"
#include "Config.h"

HuffmanNode::HuffmanNode() : right_(nullptr), left_(nullptr), weight_(0.0) {}

// create a Huffman tree node
HuffmanNode::HuffmanNode(Message &message) : weight_(message.weight_), right_(nullptr), left_(nullptr) {
    memcpy(msg_, message.content_, Constants::kMaxMsgLength);
    memcpy(nonce_, message.nonce_, Constants::kNonceLength);
}

// create an internal node
HuffmanNode::HuffmanNode(HuffmanNode *l, HuffmanNode *r, double weight) : right_(r), left_(l), weight_(weight) {
    // set message to null
    msg_[0] = {'\0'};
}

// calculate hash for a leaf node -> H(msg, nonce)
void HuffmanNode::calculateHash() {
    CryptoUtils::DoSha256(msg_, Constants::kMaxMsgLength, nonce_, Constants::kNonceLength, hash_);
}

// calculate hash for an internal node -> H(left(h), right(h))
void HuffmanNode::calculateHash(HuffmanNode *left, HuffmanNode *right) {
    CryptoUtils::DoSha256(left->hash_, Constants::kHashLength, right->hash_, Constants::kHashLength, hash_);
}
