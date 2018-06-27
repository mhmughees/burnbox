//
// Created by Haris Mughees on 3/13/18.
//

#ifndef B2_UTILPKCRYPTO_H
#define B2_UTILPKCRYPTO_H

#include <iostream>

using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#include <iomanip>
#include <string>
#include <cassert>
#include "UtilCrypto.h"

using std::string;

#include <cryptopp/ecp.h>

using CryptoPP::ECP;

#include "cryptopp/osrng.h"

using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/eccrypto.h>

using CryptoPP::ECDH;

#include <cryptopp/asn.h>
#include <cryptopp/oids.h>

using CryptoPP::OID;
using CryptoPP::ASN1::secp256r1;

#include <cryptopp/cryptlib.h>

using CryptoPP::lword;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::Exception;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::AAD_CHANNEL;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;

#include <cryptopp/secblock.h>

using CryptoPP::SecByteBlock;
using CryptoPP::SecBlock;


#include <cryptopp/filters.h>

using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;


#include <cryptopp/files.h>
using CryptoPP::FileSink;


//static AutoSeededRandomPool PRNG;
static const OID CURVE = secp256r1();



typedef unsigned char byte;
typedef CryptoPP::ECIES<ECP, CryptoPP::SHA1, CryptoPP::IncompatibleCofactorMultiplication, true> myECIES;


class UtilPKCrypto {

    static myECIES::PublicKey _pubkey;
    static myECIES::PrivateKey _seckey;
    static bool can_encrypt;
    static bool can_decrypt;

public:
    static void InitializeKey();

    static void SetSecKey(const string &sk, bool gen_pk);

    static void SetPubKey(const string &pk);

    static void SetParam();

    static void SerializeSecKey(string &s);

    static void SerializePubKey(string &s);

    static void PKEncrypt(const string &msg, string &ctx);

    static void PKDecrypt(const string &ctx, string &msg);

private:
    UtilPKCrypto() {}
};


#endif //B2_UTILPKCRYPTO_H
