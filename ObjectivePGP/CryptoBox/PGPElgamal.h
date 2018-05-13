//
//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPMPI.h"
#import "PGPTypes.h"
#import "PGPKeyMaterial.h"
#import "PGPPublicKeyPacket.h"
#import "PGPSecretKeyPacket.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPElgamal : NSObject

PGP_EMPTY_INIT_UNAVAILABLE;

// encryption
+ (nullable NSArray<PGPBigNum *> *)publicEncrypt:(NSData *)toEncrypt withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;
+ (nullable NSData *)privateDecrypt:(NSData *)toDecrypt withSecretKeyPacket:(PGPSecretKeyPacket *)secretKeyPacket gk:(PGPMPI *)gkMPI;


@end

NS_ASSUME_NONNULL_END
