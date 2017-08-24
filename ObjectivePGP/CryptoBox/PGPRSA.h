//
//  PGPPublicKeyAlgorithmRSA.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPMPI.h"
#import "PGPTypes.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPSecretKeyPacket, PGPPublicKeyPacket;

@interface PGPRSA : NSObject

PGP_EMPTY_INIT_UNAVAILABLE;

// encryption
+ (nullable NSData *)publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;
+ (nullable NSData *)privateDecrypt:(NSData *)toDecrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket;

// signature
+ (nullable NSData *)publicDecrypt:(NSData *)toDecrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;
+ (nullable NSData *)privateEncrypt:(NSData *)toEncrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket;

// new keys
+ (nullable NSSet<PGPMPI *> *)generateNewKeyMPIArray:(const int)bits algorithm:(PGPPublicKeyAlgorithm)algorithm;

@end

NS_ASSUME_NONNULL_END
