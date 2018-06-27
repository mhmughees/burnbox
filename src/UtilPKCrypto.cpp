//
// Created by Haris Mughees on 3/13/18.
//

#include "UtilPKCrypto.h"


myECIES::PublicKey UtilPKCrypto::_pubkey;
myECIES::PrivateKey UtilPKCrypto::_seckey;


 bool UtilPKCrypto::can_encrypt = false;
 bool UtilPKCrypto::can_decrypt = false;

void UtilPKCrypto::InitializeKey() {
    UtilPKCrypto::_seckey.Initialize(PRNG, CURVE);
    UtilPKCrypto::_seckey.MakePublicKey(UtilPKCrypto::_pubkey);
    can_decrypt = true;
    can_encrypt = true;


}

void UtilPKCrypto::SetSecKey(const string &sk, bool gen_pk) {
    StringSource ss((byte *) sk.data(), sk.size(), true);
    UtilPKCrypto::_seckey.Load(ss);
    //UtilPKCrypto::_seckey.BERDecode(ss);
    UtilPKCrypto:: _seckey.ThrowIfInvalid(PRNG, 3);
    if (gen_pk){
        _seckey.MakePublicKey(_pubkey);
        can_encrypt = true;
    }
    can_decrypt = true;
    SetParam();
}

void UtilPKCrypto::SetPubKey(const string &pk) {
    StringSource ss((byte *) pk.data(), pk.size(), true);
    UtilPKCrypto::_pubkey.Load(ss);
    can_encrypt = true;
    SetParam();

}



void UtilPKCrypto::SetParam() {
    UtilPKCrypto::_seckey.AccessGroupParameters().SetPointCompression(true);
    UtilPKCrypto::_pubkey.AccessGroupParameters().SetPointCompression(true);
    UtilPKCrypto::_seckey.AccessGroupParameters().SetEncodeAsOID(true);
    UtilPKCrypto::_pubkey.AccessGroupParameters().SetEncodeAsOID(true);

}

void UtilPKCrypto::SerializePubKey(string &s) {

    assert(can_encrypt);
    SetParam();
    StringSink ss(s);
    UtilPKCrypto::_pubkey.Save(ss);
    //can_encrypt=false;


}

void UtilPKCrypto::SerializeSecKey(string &s) {

    assert(can_decrypt);
    SetParam();
    StringSink ss(s);
    UtilPKCrypto::_seckey.Save(ss);
    //can_decrypt=false;


}

void UtilPKCrypto::PKEncrypt(const string &msg, string &ctx) {
    ctx.clear();
    if (!can_encrypt) throw ("can not encrypt");
    auto e = myECIES::Encryptor(UtilPKCrypto::_pubkey);
    StringSource((byte *) msg.data(), msg.size(), true, new CryptoPP::PK_EncryptorFilter(PRNG, e, new StringSink(ctx)));

}

void UtilPKCrypto::PKDecrypt(const string &ctx, string &msg) {
    msg.clear();
    if (!can_decrypt) throw ("can not decrypt");
    auto d = myECIES::Decryptor(UtilPKCrypto::_seckey);
    StringSource((byte *) ctx.data(), ctx.size(), true, new CryptoPP::PK_DecryptorFilter(PRNG, d, new StringSink(msg)));


}

