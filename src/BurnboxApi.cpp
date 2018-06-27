//
// Created by Haris Mughees on 3/8/18.
//

//#include <curses.h>
#include "BurnboxApi.h"


BurnboxApi::BurnboxApi() {


    //Init();


    //AddFile()


    //CreateInMemoryStore();



//    string err;
//
//    Init(err);
//    //CreateInMemoryStore();
//
//    /*
//
//    if (!ChkState()) {
//        LoadRevKey();
//        CreateInMemoryStore();
//
//    } else {
//        Init(err);
//        CreateInMemoryStore();
//    }
//
//     */
//
//    string testfile = "EnrollmentCertificate.pdf";
//    AddFile(testfile);
//    testfile.clear();
//    testfile = "lecnotes.pdf";
//    AddFile(testfile);
//    DeleteFile("lecnotes.pdf");
//
//
//    AddFile(testfile);
//
//    CreateInMemoryStore();
//


    //RecoverAllFiles();
    /*
    SecByteBlock b;
    int i=1;
    Tree::DeleteFile(i,b);
    CreateInMemoryStore();

    */



}


bool BurnboxApi::Init(string &err) {

    //this function cleans and reset everything I am using it for analysis, Later I will remove reset part to a seperate function

    //int indx_file = OpenCreateFile(INDX_FILE);


    bool inited= false;
    if (ChkInit(err)) {
        inited= true;
    };

    if (!inited) {
        if (!InitIndexFile()) {
            err = "Index file is not created";
            return false;
        };


        //initializing rev key
        if (!InitStoreRevkey()) {
            err = "Rev key is not initialised";
            return false;
        };





    }else{
        //if burnbox is already present then load revoke key
        //LoadRevKey();

        LoadPubRevKey();
        CreateInMemoryStore();
    }



    //if everything works well then you can recover


    //intializing all the tree conf files
    if (!Tree::Init(inited)) {
        err = "Tree files are not initialised";
        return false;
    };

    idx_read_fd = open(IDX_FILE, O_RDONLY);

    idx_write_fd = open(IDX_FILE, O_APPEND | O_WRONLY);


    return true;


}


bool BurnboxApi::InitStoreRevkey() {
    remove(REVKEY_FILE);

    if (!util::CreateFile(REVKEY_FILE, "Revkey file not created.")) {
        return false;
    };

    if (!util::CreateFile(REVPUBKEY_FILE, "Revkey file not created.")) {
        return false;
    };

    //initializing keys
    UtilPKCrypto::InitializeKey();

    if (!SaveRevKey()) {
        return false;
    };

    return true;

}


bool BurnboxApi::FileSanityChks(const string &filepath) {
    //some sanity checks about added file

    if (!boost::filesystem::exists(filepath.data())) {
        cout << "Not A Valid File" << endl;
        return false;
    };

    if (boost::filesystem::path(filepath.data()).filename().size() >= 100) {
        cout << "File name is too long, max filename is 50." << endl;
        return false;
    }

    return true;

}


bool BurnboxApi::ChkMemStore() {
    return map_loaded;
}


bool BurnboxApi::AddFile(const string &filepath, string &pname, string &err) {


    if (!ChkInit(err)) {
        return false;
    };


    cout << "adding: " << filepath.data() << endl;

    boost::filesystem::path p(filepath.data());


    //main entry function for API, it will add the file

    // simple sanity checks just to make sure that file exists and has some data
//    if (!FileSanityChks(filepath)) {
//        err = "file is not available";
//        return false;
//    }


    SecByteBlock entry_key(AES::DEFAULT_BLOCKSIZE);
    SecByteBlock revoke_key(AES::DEFAULT_BLOCKSIZE);//not using at the moment but will have to use it later
    int index = -1;


    Tree::AddFile(index, entry_key, revoke_key);




//    FILE *f = fopen("new-bb_add_kdf_time.txt", "a");
//    //printf("%.5f\n", t);
//    fprintf(f, "%.5f\n", t);
//    fclose(f);




    assert(entry_key.size() == AES::DEFAULT_BLOCKSIZE);
    if (!(index >= 0)) {
        err = "index from tree is wrong. Please check tree";
        return false;
    };

    index_entry entry;
    entry.idx = index;


    SecByteBlock content_key(AES::DEFAULT_BLOCKSIZE);
    UtilCrypto::_creatkey(content_key);

    //here file content encryption should be added


    memcpy(entry.content_key, (const char *) content_key.data(), content_key.size());



    //psuedo name
    memset(entry.pname, 0, sizeof(entry.pname));
    SecByteBlock pname_raw(AES::DEFAULT_BLOCKSIZE);
    UtilCrypto::_creatkey(pname_raw);
    UtilCrypto::b64encode((char *) pname_raw.data(), pname_raw.size(), pname);


    //if filename starts with .
    if(strncmp(filepath.data(),"/.",2)==0){
        pname= "."+ pname;
    }


    memcpy(entry.pname, pname.data(), pname.size());



    //name
    memset(entry.name, 0, sizeof(entry.name));//cleaning
    memcpy(entry.name, p.filename().string().data(), p.filename().string().size());





    // comparison
    assert(memcmp((char *) content_key.data(), entry.content_key, content_key.size()) == 0);


    // once all entry is created and all checks are passed then add it to in memory store and serialise it to storage






    int ret = (AddEncEntry(entry, entry_key, revoke_key, 0, true,
                           err));//data will be serialized only in encrypted form on storage




    if (!AddToMemStore(entry)) {

        err = "Can not be added to memory store";
        return false;
    };



//    FILE * f = fopen("new-bb_add_idx_time.txt", "a");
//    //printf("%.5f\n", t);
//    fprintf(f, "%.5f\n", t);
//    fclose(f);



//////storage testingacces
//    f = fopen("bb_idx_file_storage.txt", "a");
//
//    struct stat buffer;
//    char resolved_path[PATH_MAX];
//    realpath(IDX_FILE, resolved_path);
//    if (lstat(resolved_path, &buffer) == 0) {
//        fprintf(f, "%d\n", buffer.st_size);
//    }
//
//    fclose(f);
//
//
//    f = fopen("bb_tree_file_storage.txt", "a");
//    //struct stat buffer;
//    //char resolved_path[PATH_MAX];
//    realpath(TREE_FILE, resolved_path);
//    if (lstat(resolved_path, &buffer) == 0) {
//        auto l = fprintf(f, "%d\n", buffer.st_size);
//
//    }
//    fclose(f);


    return ret;

}


bool BurnboxApi::AddToMemStore(const index_entry &entry) {
    memstore[entry.name] = entry;

    cout << "Added:" << memstore.size() << endl;

    //map_loaded=true;


    return true;

}


bool
BurnboxApi::AddEncEntry(const index_entry &e, const SecByteBlock &key, const SecByteBlock &revkey, int idx, bool append,
                        string &err) {

    //function to add encrypted entry into the file, ciphertext will be string



    string plaintxt;
    string adata;
    string cipher;

    //serialize if to string first

    util::_structostr<index_entry>(e, plaintxt);

    //encrypt string by symmetric key
    UtilCrypto::_encrypt(key, plaintxt, adata, cipher);

    if (!(cipher.size() == IDX_ENTRY_SIZE)) {
        err = "cipher texts size does not match idx entry size. Writing to index file will be effected";
        cerr << cipher.size() << endl;
        return false;
    };

    //appending revocation cipher text

    if (append) {
        string ctx, double_ctx;

        adata.clear();

        //int ss_start = clock();
        UtilPKCrypto::PKEncrypt(plaintxt, ctx);
        //int ss_end = clock();
        //auto ss = (ss_end - ss_start);
        //auto t = (ss_end - ss_start) * 1.0 / (CLOCKS_PER_SEC / 1000);

        //cout<<"pkencccc======>"<<t<<endl;

        UtilCrypto::_encrypt(revkey, ctx, adata, double_ctx);

        //cout << "size of enc==>>" << double_ctx.size() << endl;

        cipher.append(double_ctx.data(), double_ctx.size());

        //cout<<ctx.size()<<endl;

        if (!(cipher.size() == ENTRY_SIZE)) {
            err = "cipher texts size does not match idx entry size. Writing to index file will be effected";
            return false;
        };


        return (WriteIdxToFile(cipher));
    } else {
        return (WriteIdxToFilePtr(cipher, idx));
    }


}

/**
 * @param filename name of file that needs to be deleted
 * @return
 */


bool BurnboxApi::DeleteFile(const string &filename) {


    assert(ChkState());
    if (!map_loaded) {
        assert(CreateInMemoryStore());
    }


    boost::filesystem::path p(filename.data());

    auto i = memstore.find(p.filename().string().data());

    //auto i = memstore.find(filename);

    if (!(i == memstore.end())) {


        Tree::DeleteFile(memstore[i->first].idx, false);


        memstore.erase(i);


    } else {
        printf("File does not exist in Burnbox\n");
        return false;
    }



    return true;
}


bool BurnboxApi::RevokeFile(const string &filename) {

    string err;
    if (!ChkInit(err)) {
        cerr << "There is no Burnbox existed on this machine, make sure that all files are present." << endl;
        return false;
    };

    if (!map_loaded) {
        assert(CreateInMemoryStore());
    }

    boost::filesystem::path p(filename.data());

    auto i = memstore.find(p.filename().string().data());

    //auto i = memstore.find(filename);

    if (!(i == memstore.end())) {
        Tree::DeleteFile(memstore[i->first].idx, true);
        memstore.erase(i);


    } else {
        printf("File does not exist in Burnbox");
        return false;
    }


    return true;


    return 0;
}

bool BurnboxApi::RecoverAllFiles(string &err) {

    //this function recover all the files... recovered files are then added as new files. while old cipher text of recovered files are deleted.

    if (!ChkInit(err)) {
        cerr << "There is no Burnbox existed on this machine, make sure that all files are present." << endl;
        return false;
    };


    LoadRevKey();


    LoadIdxInMemory(true);

//    if (!map_loaded) {
//        assert(CreateInMemoryStore());
//    }

    keystore.clear();
    keystore.shrink_to_fit();


    vector<SecByteBlock> revkeystore;
    //Tree::GetAllKeys(keystore);

    Tree::GetAllKeys_Recursive(keystore, revkeystore);

    index_entry e;



    for (int i = 0; i < Tree::GetKeyCount(); i++) {


        if (!ReadIdxFromMem(i, false, keystore[i], e)) {
            //first check if file is revoked or not



            SecByteBlock revkey;


            Tree::GetKey(i, revkey, true);


            if (ReadIdxFromMem(i, true, revkey, e)) {



                //decrypt using delete key

                //Tree::DeleteFile(i, false);//delete entry after recovery
                SecByteBlock idx_key(KEY_SIZE);
                SecByteBlock revoke_key(KEY_SIZE);

                //this function will add next indx and idx key into variables
                /////Tree::AddFile(index, idx_key, revoke_key);//// remove it to revert

                //e.idx = index;//remove it if recovery index is updated
                memstore[e.name] = e;



                // adding entry to same location with new idx key but old revkey



                if (!AddEncEntry(e, keystore[i], revkey, i, false, err)) {
                    return false;
                };






            } else {
                //cerr<< "Error on recovery for index "<< i<<endl;
                return false;
            }


        };
    }

    return true;
}


bool BurnboxApi::WriteIdxToFile(const string &cipher) {

    //function that always writes to the end of index file

    assert(ChkState());

    assert(cipher.size() == ENTRY_SIZE);


    int fd = idx_write_fd;
    if (fd < 0) {
        printf("%s", "index file error");
        return false;
    }

    lseek(fd, 0, SEEK_END);

    if (write(fd, cipher.data(), ENTRY_SIZE) != ENTRY_SIZE) {
        printf("%s", "index file error");
        return false;
    };


    //return (WriteToFileEnd(IDX_FILE, cipher, (int) ENTRY_SIZE, "index file error"));

    return true;

}

bool BurnboxApi::WriteIdxToFilePtr(const string &cipher, int idx) {

    //function that always writes to the end of index file

    assert(ChkState());

    //assert(cipher.size() == ENTRY_SIZE);


    int fd = idx_write_fd;

    //assert(lseek(idx_write_fd, idx * ENTRY_SIZE, See) == ENTRY_SIZE);

    if (fd < 0) {
        printf("%s", "index file error");
        return false;
    }
    if (pwrite(fd, cipher.data(), IDX_ENTRY_SIZE , idx * ENTRY_SIZE) != IDX_ENTRY_SIZE) {
        printf("%s", "index file error");
        return false;
    };


    //return (WriteToFileEnd(IDX_FILE, cipher, (int) ENTRY_SIZE, "index file error"));

    return true;

}


bool BurnboxApi::LoadIdxInMemory(bool status __attribute__((unused))) {

    int fd = open(IDX_FILE, O_RDONLY);

    struct stat buffer;
    char resolved_path[PATH_MAX];
    realpath(IDX_FILE, resolved_path);
    assert(lstat(resolved_path, &buffer) == 0);
    file_arr = new char[buffer.st_size];
    assert(read(fd, file_arr, buffer.st_size) == buffer.st_size);


    return true;


}

bool BurnboxApi::ReadIdxFromMem(const int &index, const bool rev_entry, const SecByteBlock &key, index_entry &entry) {


    assert(index >= 0);

    string cipher;
    string adata;
    string plaintext;


    //ReadFromFileIdx(IDX_FILE, (index * ENTRY_SIZE), arr, ENTRY_SIZE, "index entry not readable.");

    assert(file_arr != NULL);
    cipher.assign(file_arr + (index * ENTRY_SIZE), ENTRY_SIZE);


    if (!rev_entry) {

        if (!UtilCrypto::_decrypt(key, cipher.substr(0, IDX_ENTRY_SIZE), adata, plaintext)) {
            return false;
        };

    } else {
        string ctx;
        if (UtilCrypto::_decrypt(key, cipher.substr(IDX_ENTRY_SIZE, cipher.size()), adata, ctx)) {
            //int ss_start = clock();
            UtilPKCrypto::PKDecrypt(ctx, plaintext);
            //int ss_end = clock();
            //auto ss = (ss_end - ss_start);
            //auto t = (ss_end - ss_start) * 1.0 / (CLOCKS_PER_SEC / 1000);

            //cout << "pkenc======>" << t << endl;

        } else {
            return false;
        }

    }

//    if (!UtilCrypto::_decrypt(key, cipher, adata, plaintext)) {
//        return true;
//    };




    memcpy(&entry, plaintext.data(), plaintext.size());

    return true;

}


bool BurnboxApi::ReadIdxFromFile(const int &index, const bool rev_entry, const SecByteBlock &key, index_entry &entry) {

    //function that always writes to the end of index file


    assert(index >= 0);

    string cipher;
    string adata;
    string plaintext;

    char arr[ENTRY_SIZE];

    memset(arr, 0, sizeof(arr));

    //ReadFromFileIdx(IDX_FILE, (index * ENTRY_SIZE), arr, ENTRY_SIZE, "index entry not readable.");



    assert(pread(idx_read_fd, arr, ENTRY_SIZE, index * ENTRY_SIZE) == ENTRY_SIZE);


    cipher.assign(arr, sizeof(arr));

    if (!rev_entry) {

        if (!UtilCrypto::_decrypt(key, cipher.substr(0, IDX_ENTRY_SIZE), adata, plaintext)) {
            return false;
        };

    } else {
        string ctx;
        if (UtilCrypto::_decrypt(key, cipher.substr(IDX_ENTRY_SIZE, cipher.size()), adata, ctx)) {
            UtilPKCrypto::PKDecrypt(ctx, plaintext);
        } else {
            return false;
        }

    }



    memcpy(&entry, plaintext.data(), plaintext.size());


    return true;
}

bool BurnboxApi::CreateInMemoryStore() {
    assert(ChkState());


    LoadIdxInMemory(true);


    keystore.clear();
    keystore.shrink_to_fit();

    memstore.clear();// cleaning

/////////remove it after testing //////
    //Tree::GetAllKeys(keystore); // getting all keys from tree


    vector<SecByteBlock> revkeystore;

    Tree::GetAllKeys_Recursive(keystore, revkeystore);





    index_entry e;


    ///trying to improve speed //
    // for (int i = 0; i < keystore.size(); i++) {



    for (int i = 0; i < Tree::GetKeyCount(); i++) {

        /////////remove it after testing //////
//        SecByteBlock key;
//        Tree::GetKey(i,key,false);

        //if (ReadIdxFromFile(i, false, keystore[i], e)) {//// un comment it for loading index entries from disk
        if (ReadIdxFromMem(i, false, keystore[i], e)) {// un comment it for loading index entries from memory


            memstore[e.name] = e;

//            string ss;
//            UtilCrypto::b64encode(e.content_key, sizeof(e.content_key), ss);
//
//            cout<<"done"<<endl;
//            assert(memstore[e.name].content_key.data()==e.content_key.data());
//
//            SecByteBlock sb(reinterpret_cast<const byte *>(e.content_key), sizeof(e.content_key));
        }

    }




    delete file_arr;

    return true;
}

bool BurnboxApi::SaveRevKey() {

    //function to store revocation key in file





    string sk;
    UtilPKCrypto::SerializeSecKey(sk);
    UtilPKCrypto::SetSecKey(sk, true);
    int fd = open(".revkey.conf", O_WRONLY | O_TRUNC);
    ssize_t wc = write(fd, sk.data(), sk.size());

    close(fd);

    string pk;
    UtilPKCrypto::SerializePubKey(pk);
    fd = open(".revpubkey.conf", O_WRONLY | O_TRUNC);
    ssize_t wcc = write(fd, pk.data(), pk.size());

    (void)wcc;

    close(fd);

    //return util::WrtieToFile(".revkey.conf", sk.data(), sk.size(), "can not write rev key");

    return (wc == REVKEY_SIZE);
}

bool BurnboxApi::LoadRevKey() {
    //this function will laod rev key

    //assert(state_exist);

    string sk;
    char arr[REVKEY_SIZE];

//    if (!ReadFromFileIdx(".revkey.conf", 0, arr, REVKEY_SIZE, "revkey not readable.")) {
//        return false;
//    };




    int fd = open(".revkey.conf", O_RDONLY);
    ssize_t rc = read(fd, arr, REVKEY_SIZE);
    assert(rc == REVKEY_SIZE);

    sk.assign(arr, REVKEY_SIZE);
    assert(sk.size() == REVKEY_SIZE);

    UtilPKCrypto::SetSecKey(sk, true);
    //can_recover = true;
    return true;
}

bool BurnboxApi::LoadPubRevKey() {
    //this function will laod rev key

    //assert(state_exist);

    string pk;
    char arr[REVPUBKEY_SIZE];


    int fd = open(".revpubkey.conf", O_RDONLY);
    ssize_t rc = read(fd, arr, REVPUBKEY_SIZE);
    assert(rc == REVPUBKEY_SIZE);

    pk.assign(arr, REVPUBKEY_SIZE);
    assert(pk.size() == REVPUBKEY_SIZE);

    UtilPKCrypto::SetPubKey(pk);
    //can_recover = true;
    return true;
}

bool BurnboxApi::InitIndexFile() {


    remove(IDX_FILE);//temporary


    if (!util::CreateFile(IDX_FILE, "Index file not created.")) {
        return false;
    };



    return true;

}

bool BurnboxApi::ChkState() {


    if ((util::FileExistsTest(IDX_FILE) && util::FileExistsTest(TREE_INFO) && util::FileExistsTest(TREE_FILE) &&
         util::FileExistsTest(ROOTKEY_FILE) && util::FileExistsTest(REVKEY_FILE))) {

        return true;
    } else {

        return false;
    }

}

bool BurnboxApi::ListAllFiles(string &list, string &err) {

    if (!ChkInit(err)) {
        cerr << "There is no Burnbox existed on this machine, make sure that all files are present." << endl;
        return false;
    };

    list.clear();

    CreateInMemoryStore();// creating a new memory store



    cout << "list size:" << memstore.size() << endl;

    /////////remove it after testing //////

    for (map<string, index_entry>::iterator it = memstore.begin(); it != memstore.end(); ++it) {
        list.append(it->first);
        list.append("\n");
    }

    return true;
}

bool BurnboxApi::ChkInit(string &err) {

    if (!ChkState()) {
        err = "Burnbox not initialized. Please press init";
        return false;
    };

    return true;
}

bool BurnboxApi::PrfToName(string &prf, string &name) {


    string prf_bck=prf;
    if (strncmp(prf.data(),"._",2)==0){
        prf= prf.substr(2);
    }

    for (auto &entry: memstore) {
        if (strncmp(entry.second.pname, prf.data(), prf.size()) == 0) {

            name.assign(entry.second.name, sizeof(entry.second.name));

            if (strncmp(prf_bck.data(),"._",2)==0){
                name= "._"+name;
            }

            return true;

        }

    }


    name.clear();
    return false;
}

bool BurnboxApi::NameToPrf(string &name, string &prf) {

    /***
     * TODO: check if name does not have leading / and is not root dir
     */


    boost::filesystem::path p(name.data());



    if(strncmp(p.string().data(),"/._",3)==0)
    {

        p=p.string().substr(3);
        p= "/"+ p.string();

    }



    auto i = memstore.find(p.filename().string().data());

    if (!(i == memstore.end())) {
        prf.assign(memstore[i->first].pname, sizeof(memstore[i->first].pname));



        if(strncmp(name.data(),"/._",3)==0)
        {
            prf= "._"+prf;
        }

        return true;

    }

    prf.clear();
    return false;
}

bool BurnboxApi::NameToCK(string &name, SecByteBlock& content_key) {

    boost::filesystem::path p(name.data());

    if(strncmp(p.string().data(),"/._",3)==0)
    {

        p=p.string().substr(3);
        p= "/"+ p.string();

    }

    auto i = memstore.find(p.filename().string().data());

    if (!(i == memstore.end())) {
        content_key.Assign((byte *) memstore[i->first].content_key, AES::DEFAULT_BLOCKSIZE);
        return true;

    }


    return false;
}







