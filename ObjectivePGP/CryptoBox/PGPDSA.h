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

@class PGPSecretKeyPacket, PGPPublicKeyPacket, PGPSignaturePacket, PGPKey;

@interface PGPDSA : NSObject

PGP_EMPTY_INIT_UNAVAILABLE;

// signature
+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;

+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket error:(NSError * __autoreleasing _Nullable * _Nullable)error;

+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key;

// new keys
+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(const int)bits;

@end

NS_ASSUME_NONNULL_END
