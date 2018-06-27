//
// Created by Haris Mughees on 3/22/18.
//



#include "catch.hpp"
#include "Tree.h"
#include "Util.h"
#include "UtilCrypto.h"


//TEST_CASE("get keys test", "[getallkeys]") {
//    Tree::Init();
//    SecByteBlock testkey, revokekey;
//    vector<SecByteBlock> keystore;
//    int idx, i;
//
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    i = idx;
//    SecByteBlock tmpkey;
//
//    Tree::GetAllKeys(keystore);
//
//    cout << "idx:" << i << "keystore:" << keystore.size() << endl;
//
//    REQUIRE(keystore.size() == i + 1);
//
//
//}
//
//
//TEST_CASE("checkkey", "[getallkeys]") {
//    Tree::Init();
//    SecByteBlock testkey, revokekey;
//    SecByteBlock tmpkey;
//    vector<SecByteBlock> keystore;
//    int idx, i;
//
//    Tree::AddFile(idx, testkey, revokekey);
//    i = idx;
//    tmpkey = testkey;
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//
//
//    Tree::DeleteFile(idx, true);
//    idx = 3;
//
//    Tree::DeleteFile(idx, true);
//
//    //Tree::DeleteFile(i, true);
//
//    Tree::GetAllKeys(keystore);
//
//
//    REQUIRE(keystore[i] == tmpkey);
//
//
//}



//TEST_CASE("revoketest", "[getallkeys]") {
//    Tree::Init();
//    SecByteBlock testkey, revokekey;
//    SecByteBlock tmpkey;
//    vector<SecByteBlock> keystore;
//    int idx, i;
//
//    Tree::AddFile(idx, testkey, revokekey);
//
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//    Tree::AddFile(idx, testkey, revokekey);
//
//
//
//    idx = 3;
//
//    Tree::DeleteFile(idx, true);
//
//    //Tree::DeleteFile(i, true);
//
//
//
//
//}