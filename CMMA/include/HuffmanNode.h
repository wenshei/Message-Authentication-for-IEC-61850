#ifndef HUFFMAN_NODE_H
#define HUFFMAN_NODE_H

#include "Message.h"
#include "Constants.h"

class HuffmanNode {
public:
    unsigned char msg_[Constants::kMaxMsgLength];
    unsigned char nonce_[Constants::kNonceLength];
    double weight_;
    unsigned char hash_[Constants::kHashLength];
    int hash_len;

    HuffmanNode *right_;
    HuffmanNode *left_;

    HuffmanNode();
    HuffmanNode(Message &message);
    HuffmanNode(HuffmanNode *l, HuffmanNode *r, double weight);
    void calculateHash();
    void calculateHash(HuffmanNode *left, HuffmanNode *right);
};

#endif // HUFFMANNODE_H
