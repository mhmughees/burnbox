//
// Created by Haris Mughees on 3/2/18.
//

#ifndef B2_TREE_H
#define B2_TREE_H

#include <fstream>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <vector>
#include <boost/dynamic_bitset.hpp>
#include "UtilCrypto.h"
#include "Util.h"
#include <ctime>

using namespace std;



/**
 * This module interacts with following config files
 * tree.conf = whole tree is stored in it
 * treeinfo.conf = meta data of tree like capacity, rootnode pointer, capacity and height
 * .rootkey.conf = contains root key and must be kept in secure place like tpm
 *
 *
 * All these files are created at init and will be updated during additions and deletions
 *
 */


#define TEST_TREE_STR "tree_storage_non_step.txt"

#define TEST_TREE_STR_STEP "tree_storage_step.txt"

#define CUR_HEIGHT 1
#define TREE_FILE "tree.conf"
#define TREE_INFO "treeinfo.conf"
#define IDX_FILE "idx.conf"
#define ROOTKEY_FILE ".rootkey.conf"

#define TPM_SCRIPT "init.sh"


#define NONE 999999999

typedef basic_string<unsigned char> ustring;



struct Node {
    char cipher[48];
    char revoke_cipher[48];
    int ptr;
    int idx;
    int left_child;
    int right_child;
    bool is_leaf;
    bool is_taken;
};

struct TreeInfo {
    int root;
    int height;
    double capacity;//entry to remember max capacity of tree
    int curidx;// entry to remember next node added
};

#define  NODE_SIZE sizeof(Node)
#define  TREEINFO_SIZE sizeof(TreeInfo)
#define NODECIPHER_SIZE 48

class Tree {

public:

    static  off_t previous_size;

    static  int write_fd;

    static  int write_fd_append;

    static  int read_fd;

    static  int write_treeinfo_fd;

    static  int read_treeinfo_fd;

    static int Init(bool inited);


    static int Remove();

    static int AddFile(int &index, SecByteBlock &filekey, SecByteBlock &revokekey);

    static int DeleteFile(int &index, bool revoke);

    static void GetAllKeys(vector<SecByteBlock> &keystore);

    static int Traverser(int &height, const int &entry, const SecByteBlock &rootkey, vector<SecByteBlock> &keystor, vector<SecByteBlock> &revokekeystore);

    static int Traverser_light(int &height, const int &entry, const SecByteBlock &rootkey, vector<SecByteBlock> &keystor, bool& taken);

    static void GetAllKeys_Recursive(vector<SecByteBlock> &keystore, vector<SecByteBlock> &revokekeystore);
    static int GetKeyCount();

    static int GetNode(int &height, const int &root, const int &entry, const SecByteBlock &rootkey, Node *outputnode,
                       SecByteBlock &outputkey, bool recover);

    static int GetKey(const int &entry, SecByteBlock& key, const bool recover);

private:
    Tree() {};

    static char * keys_file;

    static bool LoadKeysInMemory(bool status);

    static void ReadNodeFromMem(const int &ptr, Node *node);


    static void ResetRootKey(SecByteBlock &newrootkey);

    static void ReadTreeInfo(TreeInfo *info);

    static void ReadRootKey(SecByteBlock &rootkey);

    static bool WriteRootKey(const SecByteBlock &rootkey);

    static void WriteTreeInfo(const TreeInfo *info);

    static int
    GenSubTree(int height, int &idx, const int &entry, const SecByteBlock &parentkey, SecByteBlock &outputkey,
               SecByteBlock &revokekey,
               int &nextidx);

    static int
    SetNode(const int &height, const int &root, const int &entry, const SecByteBlock &rootkey,
            SecByteBlock &outputkey, SecByteBlock &revokekey, int &nextidx);


    static void ReadNodeFromPtr(const int &ptr, Node *node);

    static void WriteNode(Node *node);

    static void WriteNodeToPtr(const Node *node, const int &ptr);

    static int TreeFileSize();

    static void encrypt_key(const SecByteBlock &parentkey, SecByteBlock &childkey, string &cipher);

    static void encrypt_key2(const SecByteBlock &parentkey, SecByteBlock &childkey, string &cipher);

    static void decrypt_key(const SecByteBlock &parentkey, const string &cipher, SecByteBlock &childkey);

    static void reencrypt_key(const int &ptr, const SecByteBlock &oldkey, const SecByteBlock &newkey);

    static void
    revokedeletekey(const int &ptr, const SecByteBlock &oldkey, const SecByteBlock &newkey, const bool revoke);

    static void renewnode(Node *node, SecByteBlock &oldparentkey, SecByteBlock &newparentkey, SecByteBlock &oldnodekey,
                          SecByteBlock &newnodekey);

    static void InsertEntry(TreeInfo *t1, const int &entry, const SecByteBlock &rootkey, SecByteBlock &outputkey,
                            SecByteBlock &revokekey);


    static void InsertEntry_light(TreeInfo *t1, const int &entry, const SecByteBlock &rootkey, SecByteBlock &outputkey, SecByteBlock &revokekey);

    static void
    DeleteEntry(TreeInfo *t1, const int &entry, const SecByteBlock &oldrootkey, const SecByteBlock &newrootkey,
                const bool revoke);

    static void Tree_Storage_Evaluation(TreeInfo * t, const int &index);

};


#endif //B2_TREE_H
