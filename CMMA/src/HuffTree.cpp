#include "HuffTree.h"

HuffTree::HuffTree() : root_(nullptr) {}

HuffTree::HuffTree(Message message) {
    root_ = new HuffmanNode(message);
    root_->calculateHash();
}

HuffTree::HuffTree(HuffmanNode *l, HuffmanNode *r, double weight) {
    root_ = new HuffmanNode(l, r, weight);
    root_->calculateHash(l, r);
}

HuffmanNode* HuffTree::getRoot() {
    return root_;
}

double HuffTree::getWeight() {
    return root_->weight_;
}
