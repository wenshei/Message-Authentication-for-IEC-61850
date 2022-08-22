#ifndef HUFFMAN_CODE_H
#define HUFFMAN_CODE_H

#include <map>
#include <queue>
#include <vector>
#include <chrono>

#include "HuffTree.h"
#include "HuffmanNode.h"
#include "Message.h"

// comparator to compare the weights of two huffman nodes
struct compare {
    bool operator()(HuffTree *l, HuffTree *r) {
        return (l->getWeight() > r->getWeight());
    }
};

class HuffmanCode {
    HuffTree *left_, *right_, *top_;
    std::priority_queue<HuffTree *, std::vector<HuffTree *>, compare> minHeap_;
    HuffTree *final_;

public:
    std::map<std::string, std::string> map_;

    HuffmanCode(Message* message, int size, std::chrono::_V2::system_clock::duration* duration);
    void InsertMap(HuffmanNode *root);
    HuffTree* getFinalTree();
};

#endif // HUFFMAN_CODE_H
