# BurnBox: Self-Revocable Encryption in a World Of Compelled Access


## Overview
This project is the prototype implementation of Burnbox given in the reference. BurnBox, provides self-revocable encryption: the user can temporarily disable their access to specific files stored remotely, without revealing which files were revoked during compelled searches, even if the adversary also compromises the cloud storage service. 

BurnBox is implemented as a userspace file system that is mounted on the underlying filesystem of the OS. It handles all the sensitive operations (key derivation, encrypted/ decryption) in memory and only forwards encrypted content to the underlying file system. 

## Build Requirements
The project can be build using cmake built system. Cmake can be installed from [here](https://cmake.org/install/).

The project requires following libraries:

* [libfuse: A user space file system library](https://github.com/libfuse/libfuse)

For MacOS install [osxfuse](https://osxfuse.github.io) and for ubuntu install 2.8.0 because recent versions of fuse are not compatible with the projects built on osxfuse. 

*  [Cryptopp: For all cryptographic functions](https://www.cryptopp.com)

This project uses Cryptopp version 7.0.0. For MacOS, you can simply do  

    brew install cryptopp

For Linux you can grab version 7.0.0 from [project repo] (https://github.com/weidai11/cryptopp/releases). After that do **make** and **make install**.

   



* [Boost: For file path validations](https://www.boost.org)

This project uses boost version 1.67.0 or above. For Mac OS, you can do
 
    brew install boost

For Linux based systems you can follow the instructions given in this [link](https://waqarrashid33.blogspot.com/2017/12/installing-boost-166-in-ubuntu-1604.html)

## Compile
In the root folder for the project run following:

    mkdir _build
    cd _build
    cmake ..

This will generate required makefile. Afterwords use ** make** that will create **burnbox** executable in **_build/src/** folder.

Further information on compiling with cmake can be found in [CMake by Example](https://mirkokiefer.com/cmake-by-example-f95eb47d45b1).

## Usage
Burnbox is implemented as a mix of standalone files system and command lines utilities. 
To run Burnbox file system:

    ./burnbox -f ufolder bb
ufolder is a folder of underlying file system where burnbox will be mounted and bb is mount name. bb can be replaced with any other name. 

bb will now appear in the filesystem. When a file is added into bb, an encrypted

To list all the files currently stored in Burnbox:

    ./burnbox ls

To revoke a particular file:

    ./burnbox revoke filename

To restore all the revoked files:

    ./burnbox restore

## Burnbox Related Files
Burnbox adds following files in the underlying filesystem. 

* idx.conf: encrypted material for burnbox index

* tree.conf: key material for key derivation

* .revkey.conf: the secret key for restoration

* .revpubkey.conf: the public key for restoration

* .rootkey.conf: root key of tree-based key derivation
