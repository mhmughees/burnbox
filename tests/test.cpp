//
// Created by Haris Mughees on 3/22/18.
//



#include "catch.hpp"
#include "Tree.h"
#include "Util.h"
#include "UtilCrypto.h"






TEST_CASE("index test","checks sequence "){
    int idx, test_idx;
    Tree::Init();
    SecByteBlock testkey, revokekey;
    Tree::AddFile(idx,testkey,revokekey);
    test_idx=idx;
    Tree::AddFile(idx,testkey,revokekey);
    REQUIRE(test_idx+1==idx);
    test_idx=idx;
    Tree::AddFile(idx,testkey,revokekey);
    REQUIRE(test_idx+1==idx);
    test_idx=idx;
    Tree::AddFile(idx,testkey,revokekey);
    REQUIRE(test_idx+1==idx);
}








