#ifndef PROOFNODE_H
#define PROOFNODE_H

#include "Constants.h"

struct ProofNode {
    unsigned char hash_[Constants::kHashLength];
    int isHashLocationRight_;
};

#endif // PROOFNODE_H
