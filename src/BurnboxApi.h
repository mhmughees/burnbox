//
// Created by Haris Mughees on 3/8/18.
//


#include <fstream>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <map>
#include <ctime>
#include <iostream>
#include <chrono>
#include <boost/dynamic_bitset.hpp>
#include <boost/filesystem.hpp>
#include "UtilPKCrypto.h"
#include "UtilCrypto.h"
#include "Util.h"

#include "Tree.h"


#ifndef B2_INDEX_H
#define B2_INDEX_H


using namespace std;
using namespace util;


/**
 * Structure that holds data for each entry in idx
 */

#define SI 16


typedef struct {
    char name[100];
    int idx;
    char content_key[16];
    char pname[100];
} index_entry;

/////jsut for the sake of graphs///////
#define TEST_ADD_TIME "4test_add_time.txt"
#define TEST_LOAD_TIME "test_load_time.txt"
#define TEST_IDX_STR "test_index_store.txt"
#define TEST_ACCESS_TIME "test_access_time.txt"
#define TEST_R_LOAD_TIME "test_recur_load_time.txt"
#define TEST_DEL_TIME "test_del_time.txt"
#define TEST_ACCESS_TIME "test_access_time.txt"
#define TEST_TREE_STR "tree_storage_non_step.txt"


#define IDX_FILE "idx.conf"
#define REVKEY_FILE ".revkey.conf"
#define REVPUBKEY_FILE ".revpubkey.conf"

#define DEL_FILE "del.conf"


#define REVKEY_SIZE 67 //ec key need to find better way to measure it
#define REVPUBKEY_SIZE 59
#define KEY_SIZE AES::DEFAULT_BLOCKSIZE

#define IDX_ENTRY_SIZE (sizeof(index_entry)+32) //symmetric
#define REV_ENTRY_SIZE 273 + 32  //ec encryption size need to find better way to measure it, its public key encryption
#define ENTRY_SIZE (IDX_ENTRY_SIZE+REV_ENTRY_SIZE) //525 at the moment

#define FILE_CHUNK 500
#define REC_ENC (sizeof(100*char)+ sizeof(int)+ sizeof())
#define FILE_CHUNK_ENC (FILE_CHUNK+MAC_SIZE+AES::DEFAULT_BLOCKSIZE)


class BurnboxApi {


    map<string, index_entry> memstore;
    vector<SecByteBlock> keystore;




public:


    BurnboxApi();

    bool Init(string &err);

    bool AddFile(const string &filepath, string & pname, string &err);

    bool DeleteFile(const string &filename);

    bool RevokeFile(const string &filename);

    bool RecoverAllFiles(string &err);

    bool ListAllFiles(string &list, string &err);

    bool PrfToName( string& prf,  string& name);

    bool NameToPrf( string& name,  string& prf);

    bool NameToCK(string& name,  SecByteBlock& content_key);


private:


    bool map_loaded = false;

    int idx_write_fd=-1;

    int idx_read_fd=-1;


    char * file_arr=NULL;


    bool LoadIdxInMemory(bool status);

    bool ReadIdxFromMem(const int &index, const bool rev_entry, const SecByteBlock &key, index_entry &entry);

    bool ChkInit(string &err);

    bool FileSanityChks(const string &filepath);

    bool CreateInMemoryStore();

    bool InitStoreRevkey();

    bool SaveRevKey();

    bool SavePubRevKey();

    bool LoadRevKey();

    bool LoadPubRevKey();

    bool AddToMemStore(const index_entry &entry);

    bool WriteIdxToFile(const string &entry);

    bool WriteIdxToFilePtr(const string &cipher, int idx);

    bool AddEncEntry(const index_entry &e, const SecByteBlock &key, const SecByteBlock &revkey, int idx , bool append ,string &err);

    bool ReadIdxFromFile(const int &index, const bool rev_entry, const SecByteBlock &key, index_entry &entry);

    bool InitIndexFile();

    bool ChkState();


    bool ChkMemStore();

};


#endif //B2_INDEX_H