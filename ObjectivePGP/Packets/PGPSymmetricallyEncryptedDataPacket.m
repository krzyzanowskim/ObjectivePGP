//
//  PGPSymmetricallyEncryptedDataPacket.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 11/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Parse only

#import "PGPSymmetricallyEncryptedDataPacket.h"
#import "PGPCryptoCFB.h"
#import "PGPCryptoUtils.h"
#import "PGPPublicKeyPacket.h"

#import <CommonCrypto/CommonCrypto.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

#import <openssl/aes.h>
#import <openssl/blowfish.h>
#import <openssl/camellia.h>
#import <openssl/cast.h>
#import <openssl/des.h>
#import <openssl/idea.h>
#import <openssl/sha.h>

@implementation PGPSymmetricallyEncryptedDataPacket

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    self.encryptedData = [packetBody copy];

    return position;
}

- (NSData *)export:(NSError *__autoreleasing *)error {
    NSAssert(self.encryptedData, @"Need encrypted data, use PGPSymmetricallyEncryptedIntegrityProtectedDataPacket instead");
    if (!self.encryptedData) return nil;

    return self.encryptedData;
}

@end
