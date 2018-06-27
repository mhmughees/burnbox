//
// Created by Haris Mughees on 3/5/18.
//

#include "UtilCrypto.h"

bool UtilCrypto::_encrypt(const SecByteBlock &key, const string &plaintext, const string &extra_data,
                          string &cipher) {

    try {

        GCM<AES, CryptoPP::GCM_2K_Tables>::Encryption encryptor;

        cipher.clear();


        assert(key.size() == AES::DEFAULT_BLOCKSIZE);
        SecByteBlock iv(AES::DEFAULT_BLOCKSIZE);

        PRNG.GenerateBlock(iv, AES::DEFAULT_BLOCKSIZE);

        encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
        StringSink *cipher_sink = new StringSink(cipher);

        AuthenticatedEncryptionFilter ef(
                encryptor, cipher_sink, false, MAC_SIZE
        );

        cipher_sink->Put(iv, iv.size(), true);

        if (!extra_data.empty()) {
            ef.ChannelPut(AAD_CHANNEL, (const byte *) extra_data.data(), extra_data.size(), true);
            ef.ChannelMessageEnd(AAD_CHANNEL);
        }

        ef.ChannelPut(DEFAULT_CHANNEL, (const byte *) plaintext.data(), plaintext.size(), true);
        ef.ChannelMessageEnd(DEFAULT_CHANNEL);
    }
    catch (CryptoPP::Exception &e) {
        return false;
    }
    return true;

}

bool UtilCrypto::_decrypt(const SecByteBlock &key, const string &cipher, const string &extra_data,
                          string &plaintext) {
    try {

        GCM<AES, CryptoPP::GCM_2K_Tables>::Decryption d;

        plaintext.clear();
        string iv = cipher.substr(0, AES::BLOCKSIZE);
        string enc = cipher.substr(AES::BLOCKSIZE, cipher.length() - MAC_SIZE - AES::BLOCKSIZE);
        string mac = cipher.substr(cipher.length() - MAC_SIZE);


        assert(iv.size() == AES::BLOCKSIZE);
        assert(mac.size() == MAC_SIZE);
        assert(cipher.size() == iv.size() + enc.size() + mac.size());

        d.SetKeyWithIV(key, key.size(), (const byte *) iv.data(), iv.size());

        AuthenticatedDecryptionFilter df(d, new StringSink(plaintext),
                                         AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                         AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                         MAC_SIZE);

        df.ChannelPut(DEFAULT_CHANNEL, (const byte *) mac.data(), mac.size());
        df.ChannelPut(AAD_CHANNEL, (const byte *) extra_data.data(), extra_data.size());
        df.ChannelPut(DEFAULT_CHANNEL, (const byte *) enc.data(), enc.size());

        df.ChannelMessageEnd(AAD_CHANNEL);
        df.ChannelMessageEnd(DEFAULT_CHANNEL);
        assert(df.GetLastResult());

    }
    catch (CryptoPP::Exception &e) {
        return false;
    }

    return true;

}

void UtilCrypto::_creatkey(SecByteBlock &key) {
    key.resize(AES::DEFAULT_BLOCKSIZE);
    PRNG.GenerateBlock(key, key.size());
}


void UtilCrypto::_keywrapping(const SecByteBlock &parentkey, const SecByteBlock &childkey, string &cipher) {

    string childkeystr(reinterpret_cast<const char *>(childkey.data()), childkey.size());//convert childkey into string

    assert(childkeystr.size() == 16);
    string adata = "";//no use so thats why no value
    _encrypt(parentkey, childkeystr, adata, cipher);


}

void UtilCrypto::_keyunwrapping(const SecByteBlock &parentkey, const string &cipher, SecByteBlock &childkey) {

    string adata = "";
    string childkeystr;
    _decrypt(parentkey, cipher, adata, childkeystr);
    childkey.Assign((const byte *) childkeystr.data(), childkeystr.size());
    //SecByteBlock k3((const byte *)output.data(),output.size());

}

void UtilCrypto::_getfilenamefrompath(const string &path, string &filename) {

    filename = basename((char *) &path);

}

void
UtilCrypto::_encryptfile(const SecByteBlock &key, const string &plaintext, const string &extra_data, string &cipher) {

    GCM<AES, CryptoPP::GCM_2K_Tables>::Encryption encryptor;


    assert(key.size() == AES::DEFAULT_BLOCKSIZE);
    SecByteBlock iv(AES::DEFAULT_BLOCKSIZE);

    PRNG.GenerateBlock(iv, AES::DEFAULT_BLOCKSIZE);

    encryptor.SetKeyWithIV(key, key.size(), iv, iv.size());
    StringSink *cipher_sink = new StringSink(cipher);

    AuthenticatedEncryptionFilter ef(
            encryptor, cipher_sink, false, MAC_SIZE
    );

    cipher_sink->Put(iv, iv.size(), true);

    if (!extra_data.empty()) {
        ef.ChannelPut(AAD_CHANNEL, (const byte *) extra_data.data(), extra_data.size(), true);
        ef.ChannelMessageEnd(AAD_CHANNEL);
    }

    ef.ChannelPut(DEFAULT_CHANNEL, (const byte *) plaintext.data(), plaintext.size(), true);
    ef.ChannelMessageEnd(DEFAULT_CHANNEL);


}

void
UtilCrypto::_decryptfile(const SecByteBlock &key, const string &cipher, const string &extra_data, string &plaintext) {


    GCM<AES, CryptoPP::GCM_2K_Tables>::Decryption d;

    //plaintext.clear();
    string iv = cipher.substr(0, AES::BLOCKSIZE);
    string enc = cipher.substr(AES::BLOCKSIZE, cipher.length() - MAC_SIZE - AES::BLOCKSIZE);
    string mac = cipher.substr(cipher.length() - MAC_SIZE);


    assert(iv.size() == AES::BLOCKSIZE);
    assert(mac.size() == MAC_SIZE);
    assert(cipher.size() == iv.size() + enc.size() + mac.size());

    d.SetKeyWithIV(key, key.size(), (const byte *) iv.data(), iv.size());

    AuthenticatedDecryptionFilter df(d, new StringSink(plaintext),
                                     AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
                                     AuthenticatedDecryptionFilter::THROW_EXCEPTION,
                                     MAC_SIZE);

    df.ChannelPut(DEFAULT_CHANNEL, (const byte *) mac.data(), mac.size());
    df.ChannelPut(AAD_CHANNEL, (const byte *) extra_data.data(), extra_data.size());
    df.ChannelPut(DEFAULT_CHANNEL, (const byte *) enc.data(), enc.size());

    df.ChannelMessageEnd(AAD_CHANNEL);
    df.ChannelMessageEnd(DEFAULT_CHANNEL);

    assert(df.GetLastResult());

}
















