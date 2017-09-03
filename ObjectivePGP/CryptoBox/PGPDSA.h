//
//  PGPDSA.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
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
+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key;

// new keys
+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(const int)bits;

@end

NS_ASSUME_NONNULL_END
