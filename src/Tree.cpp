//
// Created by Haris Mughees on 3/2/18.
//

//using namespace std;

#include "Tree.h"

/*
Tree::Tree() {

    //testing here: we want to add entries and get keys

    remove(TREE_FILE);
    remove(TREE_INFO);

    TreeInfo *t1 = new TreeInfo();
    ReadTreeInfo(t1);


    SecByteBlock rootkey;
    SecByteBlock outputkey;
    UtilCrypto::_creatkey(rootkey);

    int entry = 0;
    InsertEntry(t1, entry, rootkey, outputkey);

    entry = 1;
    InsertEntry(t1, entry, rootkey, outputkey);

    entry = 2;
    InsertEntry(t1, entry, rootkey, outputkey);


    entry = 3;
    InsertEntry(t1, entry, rootkey, outputkey);

    entry = 4;
    InsertEntry(t1, entry, rootkey, outputkey);


    //starting test
    Node *outnode = new Node();
    SecByteBlock outputkey1;

    //GetNode(t1->height, t1->root, 2, rootkey, outnode, outputkey2);
    GetNode(t1->height, t1->root, 2, rootkey, outnode, outputkey1);

    SecByteBlock newrootkey;
    UtilCrypto::_creatkey(newrootkey);
    DeleteEntry(t1, 2, rootkey, newrootkey);

    SecByteBlock outputkey2;
    GetNode(t1->height, t1->root, 2, newrootkey, outnode, outputkey2);


    string test = "haris";
    string adata = "";
    string cipher;
    UtilCrypto::_encrypt(outputkey1, test, adata, cipher);

    string test_output = "";
    UtilCrypto::_decrypt(outputkey2, cipher, adata, test_output);

    printf("\n\noutput: %s\n", test_output.c_str());
    //assert(outputkey == outputkey2);

    WriteTreeInfo(t1);//write state back


}

*/


  off_t Tree::previous_size=0;

  int Tree::write_fd = -1;
 int Tree::write_fd_append=-1;

  int Tree::read_fd = -1;

  int Tree::write_treeinfo_fd=-1;

  int Tree::read_treeinfo_fd=-1;

  char * Tree::keys_file= NULL;



void Tree::InsertEntry_light(TreeInfo *t1, const int &entry, const SecByteBlock &rootkey, SecByteBlock &outputkey,
                             SecByteBlock &revokekey) {


    if (t1->height == 0 && t1->root == 0) {

        assert(t1->root == entry);

        Node node;
        node.idx = entry;

        node.is_taken = true;
        node.is_leaf = true;

        string cipher;
        SecByteBlock childkey;
        encrypt_key(rootkey, childkey, cipher);

        memcpy(node.cipher, cipher.data(), cipher.size());

        memset(node.revoke_cipher, 0, NODECIPHER_SIZE);

        string revoke_cipher;
        SecByteBlock revoke_key;
        encrypt_key(rootkey, revoke_key, revoke_cipher);
        memcpy(node.revoke_cipher, revoke_cipher.data(), revoke_cipher.size());


        node.right_child = 0;
        node.left_child = 0;

        node.ptr = TreeFileSize(); //ptr is location of node in file, check it write before writing

        WriteNode(&node);
        t1->root = node.ptr;//changing root because node is added now


        t1->height = 0;
        t1->capacity = pow(2, t1->height);
        t1->curidx = 0;//first node indx

        //return new key
        outputkey = childkey;

        revokekey = revoke_key;

        return;

    } else if (entry >= (pow(2, t1->height))) {
        //tree height changes

        Node newroot;//creating new root
        newroot.idx = entry;
        newroot.is_taken = false;
        newroot.is_leaf = false;

        //node can not fit so create a new key for root
        string cipher;
        SecByteBlock newrootkey;
        encrypt_key(rootkey, newrootkey, cipher);//encrypt and add key in newrootkey and cipher
        memcpy(newroot.cipher, cipher.data(), cipher.size());

        //for left child:


        newroot.left_child = t1->root;// previous root become left child

        newroot.right_child = NONE;


        reencrypt_key(t1->root, rootkey, newrootkey);// re encrypting previous root with newroot key




        //writing new root
        newroot.ptr = TreeFileSize();


        WriteNode(&newroot);

        //updating tree state
        t1->height = t1->height + 1;
        t1->root = newroot.ptr;
        t1->capacity = (pow(2, t1->height));


    }


    if (entry < (pow(2, t1->height))) {
        //tree height will remain same
        const boost::dynamic_bitset<> bitset1(t1->height, entry);

        Node node;
        ReadNodeFromPtr(t1->root, &node);
        SecByteBlock nodekey;
        SecByteBlock parentkey = rootkey;

        string cipher(node.cipher, NODECIPHER_SIZE);

        decrypt_key(parentkey, cipher, nodekey);


        for (int i = (int) bitset1.size() - 1; i >= 0; i--) {


            parentkey = nodekey;

            WriteNodeToPtr(&node, node.ptr);

            if (bitset1[i] == 0) {
                //move left


                if (node.left_child == NONE) {
                    //if there is no left child node then create it

                    Node childnode;

                    string cipher;
                    SecByteBlock childnodekey;
                    encrypt_key(parentkey, childnodekey, cipher);
                    memcpy(childnode.cipher, cipher.data(), cipher.size());
                    childnode.left_child = NONE;
                    childnode.right_child = NONE;
                    memset(childnode.revoke_cipher, 0, sizeof(NODECIPHER_SIZE));// just cleaning

                    childnode.is_leaf = false;
                    childnode.is_taken = false;


                    childnode.ptr = TreeFileSize();

                    node.left_child = childnode.ptr;


                    WriteNodeToPtr(&node, node.ptr);

                    nodekey = childnodekey;
                    node = childnode;

                } else {

                    //if there is left child then read it

                    Node childnode;
                    ReadNodeFromPtr(node.left_child, &childnode);
                    node = childnode;

                    string cipher2(node.cipher, NODECIPHER_SIZE);

                    decrypt_key(parentkey, cipher2, nodekey);

                }


            } else if (bitset1[i] == 1) {
                //move right

                if (node.right_child == NONE) {
                    //if there is no right child then create one

                    Node childnode;

                    string cipher;
                    SecByteBlock childnodekey;
                    encrypt_key(parentkey, childnodekey, cipher);
                    memcpy(childnode.cipher, cipher.data(), cipher.size());
                    childnode.left_child = NONE;
                    childnode.right_child = NONE;
                    memset(childnode.revoke_cipher, 0, sizeof(NODECIPHER_SIZE));// just cleaning

                    childnode.is_leaf = false;
                    childnode.is_taken = false;

                    childnode.ptr = TreeFileSize();

                    node.right_child = childnode.ptr;


                    WriteNodeToPtr(&node, node.ptr);

                    nodekey = childnodekey;

                    node = childnode;

                } else {
                    //if there is right child then just read it

                    Node childnode;
                    ReadNodeFromPtr(node.right_child, &childnode);
                    node = childnode;

                    string cipher2(node.cipher, NODECIPHER_SIZE);

                    decrypt_key(parentkey, cipher2, nodekey);

                }


            }


        }


        node.is_taken = true;
        node.is_leaf = true;
        node.right_child = 0;
        node.left_child = 0;

        string revoke_cipher;
        SecByteBlock revoke_key;
        encrypt_key(parentkey, revoke_key, revoke_cipher);
        memcpy(node.revoke_cipher, revoke_cipher.data(), revoke_cipher.size());

        node.idx = entry;

        t1->curidx = entry;


        outputkey = nodekey;

        revokekey = revoke_key;


        WriteNodeToPtr(&node, node.ptr);


    }

}


void Tree::InsertEntry(TreeInfo *t1, const int &entry, const SecByteBlock &rootkey, SecByteBlock &outputkey,
                       SecByteBlock &revokekey) {
    // reading current state of tree




    if (t1->root == 0) {
        //tree was empty so we will only add one node

        assert(t1->root == entry);

        Node node;
        node.idx = entry;

        node.is_taken = true;
        node.is_leaf = true;

        string cipher;
        SecByteBlock childkey;
        encrypt_key(rootkey, childkey, cipher);

        memcpy(node.cipher, cipher.data(), cipher.size());

        memset(node.revoke_cipher, 0, NODECIPHER_SIZE);

        string revoke_cipher;
        SecByteBlock revoke_key;
        encrypt_key(rootkey, revoke_key, revoke_cipher);
        memcpy(node.revoke_cipher, revoke_cipher.data(), revoke_cipher.size());


        node.right_child = 0;
        node.left_child = 0;

        node.ptr = TreeFileSize(); //ptr is location of node in file, check it write before writing

        WriteNode(&node);
        t1->root = node.ptr;//changing root because node is added now


        t1->height = 0;
        t1->capacity = pow(2, t1->height);
        t1->curidx = 0;//first node indx

        //return new key
        outputkey = childkey;

        revokekey = revoke_key;

    } else if (t1->root > 0) {

        //assert(t1->curidx + 1 ==
        //      entry);//to make sure that entries are added in sequence other wise things can get messy

        //tree has something so now check if index can fit in tree
        if (entry >= (pow(2, t1->height))) {
            //entry can not fit, create new root new and right sub tree, finally rencrypt previous with new root key

            Node newroot;//creating new root
            newroot.idx = entry;
            newroot.is_taken = false;
            newroot.is_leaf = false;

            //node can not fit so create a new key for root
            string cipher;
            SecByteBlock newrootkey;
            encrypt_key(rootkey, newrootkey, cipher);//encrypt and add key in newrootkey and cipher
            memcpy(newroot.cipher, cipher.data(), cipher.size());

            //for left child:
            newroot.left_child = t1->root;// previous root become left child
            reencrypt_key(t1->root, rootkey, newrootkey);// re encrypting previous root with newroot key


            //for right child
            int startidx = (int) t1->capacity;//previous capacity
            int height = t1->height;//previous height
            int nextidx = t1->curidx;

            newroot.right_child = GenSubTree(height, startidx, entry, newrootkey, outputkey, revokekey, nextidx);

            //writing new root
            newroot.ptr = TreeFileSize();
            WriteNode(&newroot);

            //updating tree state
            t1->height = t1->height + 1;
            t1->root = newroot.ptr;
            t1->capacity = (pow(2, t1->height));

            //check to confirm that next entry is added in sorted order
            assert(t1->curidx + 1 == nextidx);
            t1->curidx = nextidx;


        } else if (entry < (pow(2, t1->height))) {
            int height = t1->height;
            int root = t1->root;

            int nextidx = t1->curidx;

            SetNode(height, root, entry, rootkey, outputkey, revokekey, nextidx);
            assert(t1->curidx + 1 == nextidx);
            t1->curidx = nextidx;

        }
    }


}


int
Tree::SetNode(const int &height, const int &root, const int &entry, const SecByteBlock &rootkey,
              SecByteBlock &outputkey, SecByteBlock &revokekey, int &nextidx) {
    //function to add an entry when tree has space
    // logic: this function will be called when tree has space, so it traverse entry path and eventually returns key in outputkey

    Node *node = new Node();
    ReadNodeFromPtr(root, node);


    SecByteBlock nodekey;
    SecByteBlock parentkey = rootkey;

    assert(parentkey == rootkey);
    string cipher(node->cipher, NODECIPHER_SIZE);

    decrypt_key(parentkey, cipher, nodekey);


    const boost::dynamic_bitset<> bitset1(height, entry);


    //need to check this I am converting size_t to int by casting
    for (int i = (int) bitset1.size() - 1; i >= 0; i--) {
        parentkey = nodekey;
        assert(parentkey.size() == nodekey.size());

        if (bitset1[i] == 0) {
            ReadNodeFromPtr(node->left_child, node);
            cipher.clear();
            cipher.assign(node->cipher, NODECIPHER_SIZE);
            //assert(cipher.data()==node->cipher);
            decrypt_key(parentkey, cipher, nodekey);


        } else if (bitset1[i] == 1) {
            ReadNodeFromPtr(node->right_child, node);
            cipher.clear();
            cipher.assign(node->cipher, NODECIPHER_SIZE);
            //assert(cipher.data()==node->cipher);
            decrypt_key(parentkey, cipher, nodekey);
        }
    }

    if (node->idx == entry && node->is_leaf) {
        assert(!node->is_taken);
        node->is_taken = true;
        nextidx = node->idx;

        WriteNodeToPtr(node, node->ptr);
        outputkey = nodekey;

        cipher.clear();
        cipher.assign(node->revoke_cipher, NODECIPHER_SIZE);

        decrypt_key(parentkey, cipher, revokekey);

        delete node;
        return 1;

    }

    delete node;
    return 0;

}


void Tree::GetAllKeys_Recursive(vector<SecByteBlock> &keystore, vector<SecByteBlock> &revokekeystore) {

    TreeInfo *t1 = new TreeInfo();
    ReadTreeInfo(t1);
    bool b = true;
    LoadKeysInMemory(b);//testing for in memory keys

    SecByteBlock tmpkey(AES::DEFAULT_BLOCKSIZE);
    SecByteBlock rootkey(AES::DEFAULT_BLOCKSIZE);

    ReadRootKey(rootkey);
    assert(rootkey.size() == AES::DEFAULT_BLOCKSIZE);


    keystore.clear();

    int height = t1->height;
    int root = t1->root;

    if (t1->root > 0) {
        Traverser(height, root, rootkey, keystore, revokekeystore);
    }

    delete (t1);


}


int Tree::Traverser_light(int &height, const int &entry, const SecByteBlock &rootkey, vector<SecByteBlock> &keystor,
                          bool &taken) {
    Node node;
    ReadNodeFromPtr(entry, &node);

    SecByteBlock nodekey;
    SecByteBlock parentkey = rootkey;
    string cipher(node.cipher, NODECIPHER_SIZE);

    decrypt_key(parentkey, cipher, nodekey);

    parentkey = nodekey;

    if (node.is_leaf) {

        if (node.is_taken) {
            keystor.push_back(nodekey);
            return 1;
        } else if (!node.is_taken) {
            taken = true;
            return 1;
        }
    }


    //height= height-1;
    int left = node.left_child;
    int right = node.right_child;

    if (!taken && left != NONE) {
        Traverser_light(height, left, parentkey, keystor, taken);
    }

    if (!taken && right != NONE) {
        Traverser_light(height, right, parentkey, keystor, taken);
    }

    return 1;

}


int Tree::Traverser(int &height, const int &entry, const SecByteBlock &rootkey, vector<SecByteBlock> &keystor,
                    vector<SecByteBlock> &revokekeystore) {
    Node node;
    //ReadNodeFromPtr(entry, &node);//uncomment it for reading tree nodes from disk

    ReadNodeFromMem(entry, &node);//uncomment it for reading tree nodes from memory
    SecByteBlock nodekey;
    SecByteBlock parentkey = rootkey;
    string cipher(node.cipher, NODECIPHER_SIZE);

    decrypt_key(parentkey, cipher, nodekey);

    parentkey = nodekey;

    if (node.is_leaf) {

        if (node.is_taken) {
            keystor.push_back(nodekey);
            string revoke_cipher;
            SecByteBlock revokekey;
            revoke_cipher.assign(node.revoke_cipher, NODECIPHER_SIZE);
            decrypt_key(parentkey, revoke_cipher, revokekey);

            revokekeystore.push_back(revokekey);
            return 1;
        } else {
            return 1;
        }
    }


    //height= height-1;
    int left = node.left_child;
    int right = node.right_child;


    if (left != NONE)
        Traverser(height, left, parentkey, keystor,revokekeystore);

    if (right != NONE)
        Traverser(height, right, parentkey, keystor,revokekeystore);

    return 1;


}

int Tree::GetNode(int &height, const int &root, const int &entry, const SecByteBlock &rootkey, Node *outputnode,
                  SecByteBlock &outputkey, bool recover) {
    //function to get a particular node,  useful for testing all nodes and also get keys of all nodes

    Node *node = new Node();
    ReadNodeFromPtr(root, node);


    SecByteBlock nodekey;
    SecByteBlock parentkey = rootkey;
    string cipher(node->cipher, NODECIPHER_SIZE);

    decrypt_key(parentkey, cipher, nodekey);


    const boost::dynamic_bitset<> bitset1(height, entry);


    //need to check this I am converting size_t to int by casting
    for (int i = (int) bitset1.size() - 1; i >= 0; i--) {
        parentkey = nodekey;
        assert(parentkey == nodekey);

        if (bitset1[i] == 0) {
            ReadNodeFromPtr(node->left_child, node);
            cipher.assign(node->cipher, NODECIPHER_SIZE);
            //assert(cipher.data()==node->cipher);
            decrypt_key(parentkey, cipher, nodekey);

        } else if (bitset1[i] == 1) {
            ReadNodeFromPtr(node->right_child, node);
            cipher.assign(node->cipher, NODECIPHER_SIZE);
            //assert(cipher.data()==node->cipher);
            decrypt_key(parentkey, cipher, nodekey);
        }
    }

    if (node->idx == entry and node->is_taken) {

        *outputnode = *node;

        if (recover) {
            string revoke_cipher;
            SecByteBlock revokekey;
            revoke_cipher.assign(node->revoke_cipher, NODECIPHER_SIZE);
            decrypt_key(parentkey, revoke_cipher, revokekey);
            outputkey = revokekey;
        } else {
            outputkey = nodekey;

        }

        delete node;

        return 1;

    }

    delete node;

    return 0;

}


int Tree::GenSubTree(int height, int &idx, const int &entry, const SecByteBlock &parentkey, SecByteBlock &outputkey,
                     SecByteBlock &revokekey, int &nextidx) {

    //this function expands tree and create binary tree

    int left_child = 0;
    int right_child = 0;

    //generate new key for node and encrypt it with parent key
    string cipher;
    SecByteBlock newparentkey;
    encrypt_key(parentkey, newparentkey, cipher);

    if (height > 0) {
        //send childs new key

        left_child = GenSubTree(height - 1, idx, entry, newparentkey, outputkey, revokekey, nextidx);
        right_child = GenSubTree(height - 1, idx, entry, newparentkey, outputkey, revokekey, nextidx);
    }

    Node node;

    //add cipher text
    memcpy(node.cipher, cipher.data(), cipher.size());
    node.left_child = left_child;
    node.right_child = right_child;
    memset(node.revoke_cipher, 0, sizeof(NODECIPHER_SIZE));// just cleaning

    node.is_leaf = node.left_child == 0 && node.right_child == 0 ? true : false;


    if (node.is_leaf) {// only leafs has revoke keys
        string revoke_cipher;
        SecByteBlock revoke_key;
        encrypt_key(parentkey, revoke_key, revoke_cipher);
        memcpy(node.revoke_cipher, revoke_cipher.data(), revoke_cipher.size());

        node.idx = idx;
        idx = idx + 1;

        if (node.idx == entry) {
            node.is_taken = true;
            outputkey = newparentkey;
            nextidx = node.idx;
            revokekey = revoke_key;
        } else { node.is_taken = false; }


    } else {
        node.idx = idx;
    }


    // this if is checking if node is the one required by entry? remember we are adding extra nodes
    if (node.is_leaf && node.idx == entry) {
        node.is_taken = true;
        outputkey = newparentkey;
        nextidx = node.idx;
    } else { node.is_taken = false; }


    node.ptr = TreeFileSize();
    WriteNode(&node);
    return node.ptr;
}

void Tree::WriteNode(Node *node) {

    //simple function that always write to the end of file


    //cout << node->ptr << " writing " << endl;


    assert(write_fd_append > -1);
    int fd = write_fd_append;// open(TREE_FILE, O_CREAT | O_APPEND | O_WRONLY, 0666);
    if (fd < 0) {
        printf("Write Error: %d\n", fd);
    }
    if (write(fd, (void *) node, NODE_SIZE) < (long)NODE_SIZE) {
        printf("Write Error: %d\n", fd);
    }

    //close(fd);
}


void Tree::WriteNodeToPtr(const Node *node, const int &ptr) {

    //helper to write node to specific location in file


    //cout << " writing node at " << node->ptr << endl;

    assert(write_fd > -1);
    int fd = write_fd; //open(TREE_FILE, O_WRONLY, 0666);

    lseek(fd, 0, SEEK_SET);

    if (fd < 0) {
        printf("Write Error: %d\n", fd);
    }

    if (lseek(fd, (ptr - 1) * NODE_SIZE, 0) < 0) {
        printf("WriteNodeToPtr Seek Error: %d\n", fd);
    }

    if (write(fd, (void *) node, NODE_SIZE) < (long)NODE_SIZE) {
        printf("Write Error: %d\n", fd);
    }

    //close(fd);
}

void Tree::ReadNodeFromPtr(const int &ptr, Node *node) {

    // helper function to read node at ptr in tree file

    int fd = read_fd; //open(TREE_FILE, O_RDONLY, 0666);

    if (fd < 0) {
        printf("fd Read Error: %d\n", fd);
    }
    lseek(fd, 0, SEEK_SET);

    if (lseek(fd, (ptr - 1) * NODE_SIZE, 0) < 0) {
        printf("ReadNodeFromPtr Seek Error: %d\n", fd);
    }

    if (read(fd, (void *) node, NODE_SIZE) < (long)NODE_SIZE) {
        printf("ffd Read Error: %d\n", fd);
    }
    //close(fd);
}

int Tree::TreeFileSize() {

    // helper function to read current size of file, can be used to set ptr of node

    struct stat filestatus;
    stat(TREE_FILE, &filestatus);
    return filestatus.st_size / NODE_SIZE + 1;
}

void Tree::encrypt_key(const SecByteBlock &parentkey, SecByteBlock &childkey, string &cipher) {

    // helper function that encrypts childkey with parentkey and return in cipher

    UtilCrypto::_creatkey(childkey);
    UtilCrypto::_keywrapping(parentkey, childkey, cipher);
    assert(cipher.size() == NODECIPHER_SIZE);
}


void Tree::encrypt_key2(const SecByteBlock &parentkey, SecByteBlock &childkey, string &cipher) {

    // helper function that encrypts childkey with parentkey and return in cipher

    UtilCrypto::_keywrapping(parentkey, childkey, cipher);
    assert(cipher.size() == NODECIPHER_SIZE);
}


void Tree::decrypt_key(const SecByteBlock &parentkey, const string &cipher, SecByteBlock &childkey) {

    // helper function that decrypt cipher with parent key and return in childkey

    UtilCrypto::_keyunwrapping(parentkey, cipher, childkey);
    //printf("size of key %lu  \n", childkey.size());

}

void Tree::reencrypt_key(const int &ptr, const SecByteBlock &oldkey, const SecByteBlock &newkey) {

    //helper function that reads a node encrypts it with new key and overwrite it at its previous location

    //printf("root: %d\n", ptr);
    Node *node = new Node();
    ReadNodeFromPtr(ptr, node);
    string cipher(node->cipher, NODECIPHER_SIZE);

    SecByteBlock childkey;

    //start of pipe: open childkey with previous key
    decrypt_key(oldkey, cipher, childkey);



    //reencrypt it with new root
    encrypt_key2(newkey, childkey, cipher);


    memcpy(node->cipher, cipher.data(), cipher.size());


    if (node->is_leaf == true) {
        //this is to reencrypt deletion key

        string revoke_cipher;
        SecByteBlock revokekey;
        revoke_cipher.assign(node->revoke_cipher, NODECIPHER_SIZE);
        decrypt_key(oldkey, revoke_cipher, revokekey);
        revoke_cipher.clear();
        encrypt_key2(newkey, revokekey, revoke_cipher);
        memcpy(node->revoke_cipher, revoke_cipher.data(), revoke_cipher.size());

    }


    WriteNodeToPtr(node, ptr);

    delete node;

}


void Tree::revokedeletekey(const int &ptr, const SecByteBlock &oldkey, const SecByteBlock &newkey, const bool revoke) {

    Node *node = new Node();
    ReadNodeFromPtr(ptr, node);


    string cipher(node->revoke_cipher, NODECIPHER_SIZE);
    SecByteBlock childkey;

    //start of pipe: open childkey with previous key
    decrypt_key(oldkey, cipher, childkey);

    //reencrypt  delete key with new root
    if (revoke) {
        //if revoked
        encrypt_key2(newkey, childkey, cipher);//do not create new key
    } else {
        //if deleted
        encrypt_key(newkey, childkey, cipher);//creates new key as garbage
    }

    memcpy(node->revoke_cipher, cipher.data(), cipher.size());


    ///////////////////creating new revoke key /////////////////
    cipher.clear();
    cipher.assign(node->cipher, NODECIPHER_SIZE);
    decrypt_key(oldkey, cipher, childkey);
    encrypt_key(newkey, childkey, cipher);

    memcpy(node->cipher, cipher.data(), cipher.size());


    WriteNodeToPtr(node, ptr);

    delete node;


}


void Tree::WriteTreeInfo(const TreeInfo *info) {

    // function to write current state of tree into file
    int fd = open(TREE_INFO, O_CREAT | O_TRUNC | O_WRONLY, 0666);

    //int fd= write_treeinfo_fd;
    if (fd < 0) {
        printf("TREE_INFO Write Error: %d\n", fd);
    }

    if (write(fd, (void *) info, TREEINFO_SIZE) < (long)TREEINFO_SIZE) {
        printf("TREE_INFO Write Error: %d\n", fd);
    }

    close(fd);

}

void Tree::ReadTreeInfo(TreeInfo *info) {

    //function to read current state from file

    int fd = open(TREE_INFO, O_CREAT | O_RDONLY, 0666);
    if (lseek(fd, 0, 0) < 0) {
        printf("ReadTreeInfo Seek Error: %d\n", fd);
    }

    if (read(fd, (void *) info, TREEINFO_SIZE) < (long)TREEINFO_SIZE) {
        printf("Read Error: %d\n", fd);
    }
    close(fd);
}


void Tree::renewnode(Node *node, SecByteBlock &oldparentkey, SecByteBlock &newparentkey, SecByteBlock &oldnodekey,
                     SecByteBlock &newnodekey) {
    // a stub that will re encrypt node and and write it back to the file. Node is updated so have to write it

    string cipher(node->cipher, NODECIPHER_SIZE);
    decrypt_key(oldparentkey, cipher, oldnodekey);
    encrypt_key(newparentkey, newnodekey,
                cipher);//tricky function it adds new key and cipher both may be i should change it to add

    memcpy(node->cipher, cipher.data(), cipher.size());


}

void Tree::DeleteEntry(TreeInfo *t1, const int &entry, const SecByteBlock &oldrootkey, const SecByteBlock &newrootkey,
                       const bool revoke) {

    Node *node = new Node();
    ReadNodeFromPtr(t1->root, node);
    SecByteBlock oldprntkey = oldrootkey;
    SecByteBlock newprntkey = newrootkey;
    SecByteBlock oldchildkey, newchildkey;
    //preparing for traversing, loading root, generating new variables

    const boost::dynamic_bitset<> bitset1(t1->height, entry);



    if (t1->height == 0 && t1->root > 0) {

        //if root is the only node in the tree then dont use bitset
        revokedeletekey(t1->root, oldprntkey, newprntkey, revoke);

    } else {


        //if height is 1 or more
        //need to check this I am converting size_t to int by casting
        //loop does not go until last child as it will be deleted
        for (int i = (int) bitset1.size() - 1; i >= 0; i--) {

            //cout << "*===================> " << i << endl;
            //renewnode(Node *node, SecByteBlock &oldparentkey, SecByteBlock &newparentkey, SecByteBlock &oldnodekey,
            //SecByteBlock &newnodekey)
            //int rahul= 10;


            lseek(write_fd, 0, SEEK_SET);
            lseek(write_fd, t1->root * NODE_SIZE, 0);

            renewnode(node, oldprntkey, newprntkey, oldchildkey, newchildkey);
            WriteNodeToPtr(node, node->ptr);

            newprntkey = newchildkey;
            oldprntkey = oldchildkey;

            //assert(parentkey == nodekey);

            if (bitset1[i] == 0) {


                if (node->right_child != NONE)
                    reencrypt_key(node->right_child, oldprntkey, newprntkey);

                if (i > 0) {//this is to make sure that deleted node is not touched
                    if (node->left_child != NONE)
                        ReadNodeFromPtr(node->left_child, node);
                } else {

                    //only for leaf nodes
                    if (node->left_child != NONE)
                        revokedeletekey(node->left_child, oldprntkey, newprntkey, revoke);
                }
                //renewnode(node, oldprntkey, newprntkey, oldchildkey ,newchildkey);


                //cout << "decrypting" << endl;

            } else if (bitset1[i] == 1) {
                if (node->left_child != NONE)
                    reencrypt_key(node->left_child, oldprntkey, newprntkey);

                if (i > 0) {//this is to make sure that deleted node is not updated
                    if (node->right_child != NONE)
                        ReadNodeFromPtr(node->right_child, node);
                } else {

                    //only for leaf nodes
                    if (node->right_child != NONE)
                        revokedeletekey(node->right_child, oldprntkey, newprntkey, revoke);
                }
            }
        }
    }


    delete node;


}


/**
 *
 * @param rootkey  reading root key from rootfile
 */
void Tree::ReadRootKey(SecByteBlock &rootkey) {


//    char result[22];
//
//    string file_path = __FILE__;
//    string dir_path = file_path.substr(0, file_path.rfind("/"));
//
//    string script= dir_path +"/"+TPM_SCRIPT + " " + dir_path;
//    script.append(" unseal ");
//
//
//    FILE* fp= popen(script.data(),"r");
//    memset(result,0, sizeof(result));
//    fscanf(fp,"%s", result);
//
//
//    string result_string(result, 22);
//    string output;
//    UtilCrypto::b64decode(result_string, output);
//
//
//    assert(output.size()==AES::DEFAULT_BLOCKSIZE);




    int fd = open(ROOTKEY_FILE, O_RDONLY, 0666);
    if (lseek(fd, 0, 0) < 0) {
        printf("ReadRootKey Seek Error: %d\n", fd);
    }

    char arr[AES::DEFAULT_BLOCKSIZE];
    if (read(fd, (void *) &arr, AES::DEFAULT_BLOCKSIZE) < AES::DEFAULT_BLOCKSIZE) {
        printf("Reading Root Key Error: %d\n", fd);
    }
    close(fd);


    rootkey.Assign((byte *) &arr, sizeof(arr));

    //rootkey.Assign((byte *) output.data(), output.size());

}


void Tree::ResetRootKey(SecByteBlock &newrootkey) {

    UtilCrypto::_creatkey(newrootkey);

//    char result[22];
//
//    string file_path = __FILE__;
//    string dir_path = file_path.substr(0, file_path.rfind("/"));
//
//    string script= dir_path +"/"+TPM_SCRIPT + " " + dir_path;
//    string test;//= (char *) rootkey.data();
//    UtilCrypto::b64encode((char *)newrootkey.data(), newrootkey.size(), test);
//    //always sealing root key in b64 encoding for TPM
//
//    script.append(" seal ");
//    script.append(test.data());
//
//    FILE * fp= popen(script.data(),"r");
//    memset(result,0, sizeof(result));
//    fscanf(fp,"%s", result);






    int fd = open(ROOTKEY_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (lseek(fd, 0, 0) < 0) {
        printf("ResetRootKey Seek Error: %d\n", fd);
    }

    if (write(fd, newrootkey.data(), AES::DEFAULT_BLOCKSIZE) != AES::DEFAULT_BLOCKSIZE) {
        printf("Root key is not written");
        exit(1);
    };

    close(fd);

}


/**
 *
 * @param index Index for new file
 * @param filekey Key to encrypt file entry, This key is added in the tree
 * @return
 */
int Tree::AddFile(int &index, SecByteBlock &filekey, SecByteBlock &revokekey) {


    TreeInfo *t1 = new TreeInfo();
    ReadTreeInfo(t1);

    SecByteBlock rootkey;
    ReadRootKey(rootkey);
    if (t1->root == 0) {
        index = 0;
    } else {
        index = t1->curidx + 1;
    }


    //InsertEntry(t1, index, rootkey, filekey, revokekey);

    InsertEntry_light(t1, index, rootkey, filekey, revokekey);




//    f = fopen(TEST_TREE_STR_STEP, "a");
//    struct stat buffer;
//    char resolved_path[PATH_MAX];
//    realpath(TREE_FILE, resolved_path);
//    if (lstat(resolved_path, &buffer) == 0) {
//
//
//        fprintf(f, "%d\n", buffer.st_size);
//
//
//
//    }
//    fclose(f);
//
//
//    Tree_Storage_Evaluation(t1, index);


    WriteTreeInfo(t1);



    delete t1;


    return 0;
}


void Tree::Tree_Storage_Evaluation(TreeInfo *t, const int &index) {

    FILE *f = fopen(TEST_TREE_STR, "a");

    cout << "doing for index: " << index << " height " << t->height << endl;

    if (index == 0) {

        //for first entry
        struct stat buffer;
        char resolved_path[PATH_MAX];
        realpath(TREE_FILE, resolved_path);
        if (lstat(resolved_path, &buffer) == 0) {


            fprintf(f, "%lld\n", buffer.st_size);

            previous_size = buffer.st_size;


        }

    } else {
        int previous_index = index - 1;
        int previous_entries = index;

        int previous_height = (int) ceil(log2(previous_entries));

        if (t->height > previous_height) {
            int size = (int) previous_size + (t->height * 116) + 116;
            fprintf(f, "%d\n", size);
            previous_size = size;

        } else if (t->height == previous_height) {
            //bit logic

            const boost::dynamic_bitset<> bitset1(t->height, index);
            const boost::dynamic_bitset<> bitset2(t->height, previous_index);


            int diff = 0;
            for (int i = (int) bitset1.size() - 1; i >= 0; i--) {
                if (bitset1[i] != bitset2[i]) {
                    diff = diff + 1;
                }

            }
            int size = previous_size + (diff * 116);
            fprintf(f, "%d\n", size);
            previous_size = size;

        }


    }


    fclose(f);


}


int Tree::DeleteFile(int &index, bool revoke) {


    TreeInfo *t1 = new TreeInfo();
    ReadTreeInfo(t1);
    //index = index + 1;

    SecByteBlock oldrootkey;
    SecByteBlock newrootkey;
    ReadRootKey(oldrootkey);
    ResetRootKey(newrootkey);


    DeleteEntry(t1, index, oldrootkey, newrootkey, revoke);


    WriteTreeInfo(t1);

    delete t1;

    return 0;
}

int Tree::Init(bool inited) {

    //all keys are 128 bit long

    if(!inited) {

        remove(TREE_FILE);
        remove(TREE_INFO);
        remove(ROOTKEY_FILE);

        SecByteBlock newrootkey;
        UtilCrypto::_creatkey(newrootkey);

        if (!WriteRootKey(newrootkey)) {
            printf("Root key is not written");
            return false;
        };

        //creating tree info file which contains information about tree

        int fd;
        fd = open(TREE_INFO, O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            printf("Tree info file can not be created");
            return false;
        }
        close(fd);

        fd = -1;

        //creating tree file that will include all key material

        fd = open(TREE_FILE, O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            printf("Tree file can not be created");
            return false;
        }

        close(fd);

        //REMOVE:::::creating evaluation file.



        fd = open(TEST_TREE_STR, O_CREAT | O_TRUNC, 0666);
        if (fd < 0) {
            printf("eval file can not be created");
            return false;
        }

        close(fd);
    }

    write_fd_append = open(TREE_FILE, O_CREAT |O_APPEND | O_WRONLY, 0666);

    write_fd = open(TREE_FILE, O_WRONLY, 0666);

    read_fd = open(TREE_FILE, O_RDONLY, 0666);

    write_treeinfo_fd = open(TREE_INFO, O_CREAT | O_WRONLY, 0666);

    return true;
}


int Tree::GetKey(const int &entry, SecByteBlock &key, const bool recover) {

    TreeInfo *t1 = new TreeInfo();
    ReadTreeInfo(t1);

    SecByteBlock tmpkey(AES::DEFAULT_BLOCKSIZE);
    SecByteBlock rootkey(AES::DEFAULT_BLOCKSIZE);

    ReadRootKey(rootkey);
    assert(rootkey.size() == AES::DEFAULT_BLOCKSIZE);

    Node *n = new Node();

    GetNode(t1->height, t1->root, entry, rootkey, n, tmpkey, recover);

    key = tmpkey;

    delete t1;
    delete n;

    return 0;

}

int Tree::GetKeyCount() {

    TreeInfo *t1 = new TreeInfo();
    ReadTreeInfo(t1);
    int num = t1->curidx;
    if (t1->root > 0) {
        num = num + 1;
    }

    delete t1;
    return num;
}

void Tree::GetAllKeys(vector<SecByteBlock> &keystore) {

    TreeInfo *t1 = new TreeInfo();
    ReadTreeInfo(t1);

    SecByteBlock tmpkey(AES::DEFAULT_BLOCKSIZE);
    SecByteBlock rootkey(AES::DEFAULT_BLOCKSIZE);

    ReadRootKey(rootkey);
    assert(rootkey.size() == AES::DEFAULT_BLOCKSIZE);

    Node *n = new Node();

    if (t1->root > 0) {
        for (int i = 0; i <= t1->curidx; i++) {
            GetNode(t1->height, t1->root, i, rootkey, n, tmpkey, false);
            assert(tmpkey.size() == AES::DEFAULT_BLOCKSIZE);
            keystore.push_back(tmpkey);

        }
    }

    delete t1;
    delete n;


}

bool Tree::WriteRootKey(const SecByteBlock &rootkey) {



//    char result[22];
//
//    string file_path = __FILE__;
//    string dir_path = file_path.substr(0, file_path.rfind("/"));
//
//    string script= dir_path +"/"+TPM_SCRIPT + " " + dir_path;
//    string test;//= (char *) rootkey.data();
//    UtilCrypto::b64encode((char *)rootkey.data(), rootkey.size(), test);
//    //always sealing root key in b64 encoding for TPM
//
//    script.append(" seal ");
//    script.append(test.data());
//
//    FILE * fp= popen(script.data(),"r");
//    memset(result,0, sizeof(result));
//    fscanf(fp,"%s", result);







    assert(rootkey.size() == AES::DEFAULT_BLOCKSIZE);

    int fd = open(ROOTKEY_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0666);

    if (write(fd, rootkey.data(), AES::DEFAULT_BLOCKSIZE) != AES::DEFAULT_BLOCKSIZE) {
        printf("Root key is not written");
        return false;
    };
    return true;


}

bool Tree::LoadKeysInMemory(bool status) {

    int fd = open(TREE_FILE, O_RDONLY);

    status=true;

    struct stat buffer;
    char resolved_path[PATH_MAX];
    realpath(TREE_FILE, resolved_path);
    assert(lstat(resolved_path, &buffer) == 0);
    keys_file = new char[buffer.st_size];
    assert(read(fd, keys_file, buffer.st_size) == buffer.st_size);

    return false;
}

void Tree::ReadNodeFromMem(const int &ptr, Node *node) {

    string cipher;
    assert(keys_file != NULL);
    memcpy(node, keys_file + ((ptr - 1) * NODE_SIZE), NODE_SIZE);


}



















