//
// Created by Haris Mughees on 3/5/18.
//

#ifndef B2_UTILCRYPTO_H
#define B2_UTILCRYPTO_H

#include <cryptopp/cryptlib.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>

#include <cryptopp/modes.h>
#include <cryptopp/base64.h>
#include <assert.h>
#include <string>
#include <libgen.h>
#include <iostream>

using CryptoPP::SecByteBlock;
using CryptoPP::GCM;
using CryptoPP::AES;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AAD_CHANNEL;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::byte;
using CryptoPP::Base64URLEncoder;
using CryptoPP::Base64URLDecoder;



using namespace std;
//static CryptoPP::Rijndael::DEFAULT_BLOCKSIZE blocksize;

static CryptoPP::AutoSeededRandomPool PRNG;


typedef unsigned char byte;


#define MAC_SIZE 16

class UtilCrypto {




public:



    static bool _encrypt(const SecByteBlock &key, const string &plaintext, const string &extra_data, string &cipher);

    static bool _decrypt(const SecByteBlock &key, const string &cipher, const string &extra_data, string &plaintext);


    static void
    _encryptfile(const SecByteBlock &key, const string &plaintext, const string &extra_data, string &cipher);

    static void
    _decryptfile(const SecByteBlock &key, const string &cipher, const string &extra_data, string &plaintext);

    static void _creatkey(SecByteBlock &key);

    static void _keywrapping(const SecByteBlock &parentkey, const SecByteBlock &childkey, string &cipher);

    static void _keyunwrapping(const SecByteBlock &parentkey, const string &cipher, SecByteBlock &childkey);

    static void _getfilenamefrompath(const string &path, string &filename);



    static inline void b64encode(const char *raw_bytes, const int size ,string &str) {
        str.clear();
        StringSource ss((byte *)raw_bytes, size ,true, new Base64URLEncoder(new StringSink(str), true));
    }

    static inline void b64decode(const string &str, string &byte_str) {
        StringSource ss(str, true, new Base64URLDecoder(new StringSink(byte_str)));
    }


/**
 *
 * @tparam T
 * @param t
 * @param str
 *
 * this function converts any struct to string.
 */







private:
    UtilCrypto() {}

};


#endif //B2_UTILCRYPTO_H
