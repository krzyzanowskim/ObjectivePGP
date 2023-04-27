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
#import "PGPKeyMaterial.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPKey, PGPSignaturePacket, PGPBigNum;

@interface PGPEC : NSObject

PGP_EMPTY_INIT_UNAVAILABLE;

+ (nullable NSData *)generate25519PrivateEphemeralKeyWith:(NSData *)publicKeyEphemeralPart curveKind:(PGPCurve)curveKind privateKey:(NSData *)privateKey;

+ (BOOL)publicEncrypt:(nonnull NSData *)data withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket publicKey:(NSData * __autoreleasing _Nullable * _Nullable)publicKey encodedSymmetricKey:(NSData * __autoreleasing _Nullable * _Nullable)encodedSymmetricKey;

+ (NSArray<PGPMPI *> *)sign:(NSData *)toSign key:(PGPKey *)key withHashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;
+ (BOOL)verify:(NSData *)toVerify signature:(PGPSignaturePacket *)signaturePacket withPublicKeyPacket:(PGPPublicKeyPacket *)publicKeyPacket withHashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

//new keys
+ (nullable PGPKeyMaterial *)generateNewKeyMPIArray:(PGPCurve)curve;

@end

NS_ASSUME_NONNULL_END
