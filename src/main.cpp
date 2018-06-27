#include <iostream>
#include "Tree.h"
#include "UtilCrypto.h"
#include "Util.h"
#include "UtilPKCrypto.h"
#include "burnboxfs.h"
#include <typeinfo>
#include <sys/mman.h>

#include "boost/program_options.hpp"
#include "boost/filesystem.hpp"
#include <boost/variant/variant.hpp>
#include <boost/variant/get.hpp>
#include "BurnboxApi.h"
#include "ClientServer.h"
#include "burnboxfs.h"
#include <sys/mman.h>
#include <ctime>




/**
 * Todo: Only text files are supported at the moment. What should we do about non text files.
 */


namespace po = boost::program_options;
using namespace std;
using namespace ClientServer;


struct T1 {
    int i;
    int j;
    SecByteBlock key;
};


#define FILE_CHUNK 500

#define REV_ENC ((100*sizeof(char))+ sizeof(int)+ AES::DEFAULT_BLOCKSIZE)

void ResetArgs(string &cmd, string &args) {
    cmd.clear();
    args.clear();

}

void CmdDecider(int argc, char **argv, string &cmd, string &args) {
    if (strncmp(argv[2], init_command, sizeof(init_command)) == 0 ||
        strncmp(argv[2], list_command, sizeof(list_command)) == 0) {

        cmd.assign(argv[2], sizeof(argv[2]));

    }
    if (strncmp(argv[2], add_command, sizeof(add_command)) == 0 ||
        strncmp(argv[2], delete_command, sizeof(delete_command)) == 0) {
        if (argc != 4) {
            printf("Add and Delete requires one file path/ file name");
        } else {
            cmd.assign(argv[2], sizeof(argv[2]));
            args = argv[3];
            cout << "cmd: " << cmd.data() << endl;
            cout << "args: " << args.data() << endl;
        }


    }


}


#define TPM_SCRIPT "init.sh"


#include "bbfs.h"

int main(int argc, char **argv) {


/////////testing for tree////

//    int lock = mlockall(MCL_FUTURE);
//    cerr << "Locking returns status: " << lock << endl;
//
//
//   Tree::Init();
//
//    int index;
//    SecByteBlock filekey, revokekey;
//
//
//    for (int i=0; i<100000; i++) {
//
//        Tree::AddFile(index, filekey, revokekey);
//
//        Tree::DeleteFile(index, true);
//
//        cout<<"index==> "<<index<<endl;
//    }




//   vector<SecByteBlock> keystore;
//
//   Tree::GetAllKeys(keystore);
//
//    SecByteBlock key;
//
//
//    string test_plaintext= "haris";
//    string test_ciphertext;
//    string text_output_plaintext;
//    string adata;
//
//
//
//    int i=0;
//
//    Tree::GetKey(i,key,true);
//
//    UtilCrypto::_encrypt(key,test_plaintext, adata, test_ciphertext);
//
//    Tree::DeleteFile(i, true);// revoked
//
//
//    Tree::GetKey(i,key,true);
//
//
//    UtilCrypto::_decrypt(key, test_ciphertext, adata, text_output_plaintext);









/////////////////////uncomment it ///////////////////////
    if (strcmp(argv[1],"ls")==0) {

        string list, err;
        BurnboxApi b1;
        if(b1.ListAllFiles(list, err)){
            cout<<list<<endl;
            cout<<"<<<<<<<<<<<<<<<<end of list>>>>>>>>>>>>>>>>"<<endl;
        };
    }else if(strcmp(argv[1],"revoke")==0 && argc == 3){
        string list, err;
        BurnboxApi b1;
        b1.Init(err);
        string filename(argv[2]);
        if(!b1.RevokeFile(filename)){
            cerr<< "revoke error"<< endl;
        };

    }else if( strcmp(argv[1],"restore")==0){
        BurnboxApi b1;
        string err;
        b1.Init(err);
        if(!b1.RecoverAllFiles(err)){
            cerr<< "recover error"<< endl;
        }
    }
    else {
        mymomo::mymain(argc, argv);
    }
/////////////////until here //////////////////////////////


    ///////testing for burnbox api ////////
//
//    string list;
//    string testfile = "EnrollmentCertificate.pdf";
//    string pname;
//    BurnboxApi b1;
//
//    string err;
//    b1.Init(err);
//
//    for (int j = 0; j < 100000; j++) {
//
//
//        list = "";
//        testfile = "EnrollmentCertificate.pdf";
//        testfile = testfile + std::to_string(j);
//        b1.AddFile(testfile, pname, err);
//        b1.RevokeFile(testfile);
//
//        if ((j + 1) % 5000 == 0 && j != 0) {
//            b1.RecoverAllFiles(err);
//
//            //b1.ListAllFiles(list, err);
//
//
//            testfile = "EnrollmentCertificate.pdf";
//            for (int i = 0; i <= j; i++) {
//                //revoke all restored files
//
//                testfile = testfile + std::to_string(i);
//                b1.RevokeFile(testfile);
//                testfile = "EnrollmentCertificate.pdf";
//            }
//
//
//            //cout<<list<<endl;
//
//        }
//
//
//    }

//    BurnboxApi b1;
//
//    string err;
//    b1.Init(err);
//
//    string list;
//    string testfile = "EnrollmentCertificate.pdf";
//    string pname;
//    b1.AddFile(testfile, pname, err);
//    b1.RevokeFile(testfile);
//    b1.ListAllFiles(list, err);
//    b1.RecoverAllFiles(err);
//    b1.ListAllFiles(list, err);
//    b1.NameToPrf(testfile, pname);
////
////
////        b1.DeleteFile(testfile);
////
////        b1.ListAllFiles(list, err);
//
//
//
//
//
//
////        if ((i + 1) % 5000 == 0 && i != 0) {
////            b1.ListAllFiles(list, err);
////
////        }
//
//        list = "";
//        testfile = "EnrollmentCertificate.pdf";
//    }



//
//    b1.RevokeFile(testfile);
//
//    b1.PrfToName(pname, testfile);
//
//    b1.RecoverAllFiles(err);
//
//    b1.PrfToName(pname, testfile);
//
//
//    cout<< testfile.c_str() << endl;

//    string name;

    //b1.PrfToName(pname, name);





    //burnboxfs::start_fs(argc, argv);


    //Tree::test();

//
//    string cmd;
//    string args;
//
//
//    if (argc == 1) {
//
//        cout << "Burnbox needs arguments" << endl;
//
//
//    } else if (argc > 1) {
//        if (strcmp(argv[1], "--help") == 0) {
//            cout << "Burnbox Help" << endl;
//            cout << "--server      Starts a server" << endl;
//            cout << "--client      Starts a client" << endl;
//        } else if (strcmp(argv[1], "--server") == 0) {
//            cout << "Starting Server..." << endl;
//            Server();
//
//        } else if (strcmp(argv[1], "--client") == 0) {
//            if (argc < 3) {
//                cout << "Wrong entry for a client" << endl;
//                cout << "Format is: --client cmd args(filename/ path)" << endl;
//                cout << "Supported commands are Init, Add, Delete, Reset" << endl;
//            } else {
////                if (strncmp(argv[2], init_command, sizeof(init_command)) == 0) {
////                    //proto_struct pb;
////                    //memset(&pb,0, sizeof(proto_struct));
////                    ResetArgs(cmd, args);
////                    cmd.assign(argv[2], sizeof(argv[2]));
////                    cout << "Starting client socket" << endl;
////                    Client(cmd, args);
////
////                }
//
//                ResetArgs(cmd, args);
//                CmdDecider(argc, argv, cmd, args);
//
//                cout << "Starting client socket" << endl;
//                Client(cmd, args);
//
//            }
//
//
//        } else {
//            cerr << "wrong input, use help" << endl;
//            exit(EXIT_FAILURE);
//        }
//
//
//    }



    //BurnboxApi b1;
    //b1.AddFile(testfile);
    //b1.AddFile(testfile);

    //boost::filesystem::path p("/Users/harismughees/Documents/fun.txt");


    /*


    SecByteBlock key;

    UtilCrypto::_creatkey(key);

    cout<<sizeof(T1)<<endl;

    T1 t1;

    string e1;





    t1.j=0; t1.i=0; UtilCrypto::_creatkey(t1.key);

    UtilCrypto::_structostr(t1,e1);



    cout<< sizeof(t1)<<endl;



    remove("e.pdf");

    SecByteBlock contentkey;
    UtilCrypto::_creatkey(contentkey);

    int fd = open("EnrollmentCertificate.pdf", O_RDONLY);



    int fd_cipher = open("cipher.txt", O_CREAT|O_WRONLY, 0666);


    int t = 0;
    string plaintext;
    string adata;
    string cipher;

    do {

        char chunk[FILE_CHUNK];
        t = (int) read(fd, chunk, FILE_CHUNK);
        plaintext.assign(chunk, sizeof(chunk));
        UtilCrypto::_encryptfile(contentkey, plaintext, adata, cipher);
        plaintext.clear();

    } while (t > 0);

    write(fd_cipher, cipher.data(), cipher.size());


    close(fd_cipher);
    close(fd);

    int fd_output = open("output.pdf", O_CREAT | O_TRUNC | O_WRONLY,0666);
    fd_cipher = open("cipher.txt", O_RDONLY);
    t = 0;
    string file;
    string s;

    do {
        char chunk[FILE_CHUNK_ENC];
        t = (int) read(fd_cipher, chunk, FILE_CHUNK_ENC);
        s.assign(chunk, sizeof(chunk));
        UtilCrypto::_decryptfile(contentkey, s, adata, file);
        s.clear();
    } while (t > 0);


    write(fd_output, file.data(), file.size());
*/
    return 0;

}

