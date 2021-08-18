//
//  Copyright (C) Marcin Krzyżanowski <marcin@krzyzanowskim.com>
//  This software is provided 'as-is', without any express or implied warranty.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//
//

#import "PGPSecretKeyPacket.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPKey, PGPSignaturePacket;

@interface PGPEC : NSObject

PGP_EMPTY_INIT_UNAVAILABLE;

+ (nullable NSData *)generatePrivateEphemeralKeyWith:(NSData *)publicKeyEphemeralPart curveKind:(PGPCurve)curveKind privateKey:(NSData *)privateKey;
+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key;
+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket;

@end

NS_ASSUME_NONNULL_END
