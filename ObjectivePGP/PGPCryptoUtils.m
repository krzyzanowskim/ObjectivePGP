//
//  PGPCryptoUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 12/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPCryptoUtils.h"

#import <CommonCrypto/CommonCrypto.h>

#include <openssl/cast.h>
#include <openssl/idea.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/camellia.h>
#include <openssl/blowfish.h>
#include <openssl/ripemd.h>

@implementation PGPCryptoUtils

+ (NSUInteger) blockSizeOfSymmetricAlhorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
{
    switch (symmetricAlgorithm) {
        case PGPSymmetricIDEA:
            return IDEA_BLOCK;
        case PGPSymmetricTripleDES:
            return kCCBlockSize3DES;
        case PGPSymmetricCAST5:
            return kCCBlockSizeCAST;
        case PGPSymmetricBlowfish:
            return kCCBlockSizeBlowfish; // 64bit
        case PGPSymmetricAES128:
        case PGPSymmetricAES192:
        case PGPSymmetricAES256:
            return kCCBlockSizeAES128;
        case PGPSymmetricTwofish256:
            return 16; // 128bit
        default:
            break;
    }
    return NSNotFound;
}

+ (NSUInteger) keySizeOfSymmetricAlgorithm:(PGPSymmetricAlgorithm)symmetricAlgorithm
{
    switch (symmetricAlgorithm) {
        case PGPSymmetricIDEA:
            return IDEA_KEY_LENGTH;
        case PGPSymmetricTripleDES:
            return kCCKeySize3DES; //24 or 8 ?
        case PGPSymmetricCAST5:
            return kCCKeySizeMaxCAST;
        case PGPSymmetricBlowfish:
            return kCCKeySizeMaxBlowfish; // 16 bit (?)
        case PGPSymmetricAES128:
            return kCCKeySizeAES128;
        case PGPSymmetricAES192:
            return kCCKeySizeAES192;
        case PGPSymmetricAES256:
            return kCCKeySizeAES256;
        case PGPSymmetricTwofish256:
            return 16; // 128bit (??or 32)
        default:
            break;
    }
    return NSNotFound;
}

+ (NSUInteger) hashSizeOfHashAlhorithm:(PGPHashAlgorithm)hashAlgorithm
{
    switch (hashAlgorithm) {
        case PGPHashMD5:
            return CC_MD5_DIGEST_LENGTH;
        case PGPHashSHA1:
            return CC_SHA1_DIGEST_LENGTH;
        case PGPHashSHA224:
            return CC_SHA224_DIGEST_LENGTH;
        case PGPHashSHA256:
            return CC_SHA256_DIGEST_LENGTH;
        case PGPHashSHA384:
            return CC_SHA384_DIGEST_LENGTH;
        case PGPHashSHA512:
            return CC_SHA512_DIGEST_LENGTH;
        case PGPHashRIPEMD160:
            return RIPEMD160_DIGEST_LENGTH; // confirm RIPE/MD 160 value
        default:
            break;
    }
    return NSNotFound;
}

@end
