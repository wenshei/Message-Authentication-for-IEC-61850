#ifndef HUFFTREE_H
#define HUFFTREE_H

#include "HuffmanNode.h"
#include "Message.h"

class HuffTree {
private:
    HuffmanNode *root_;

public:
    HuffTree();
    HuffTree(Message message);
    HuffTree(HuffmanNode *l, HuffmanNode *r, double weight);
    HuffmanNode *getRoot();
    double getWeight();
};

#endif // HUFFTREE_H
