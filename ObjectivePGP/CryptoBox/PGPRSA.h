//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPMPI.h"
#import "PGPTypes.h"
#import "PGPKeyMaterial.h"
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
+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(const int)bits;

@end

NS_ASSUME_NONNULL_END
