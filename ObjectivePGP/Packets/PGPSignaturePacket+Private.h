//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPSignaturePacket.h"
#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignaturePacket ()

@property (nonatomic, copy, readwrite) NSArray<PGPSignatureSubpacket *> *hashedSubpackets;
@property (nonatomic, copy, readwrite) NSArray<PGPSignatureSubpacket *> *unhashedSubpackets;

PGP_EMPTY_INIT_UNAVAILABLE

+ (PGPSignaturePacket *)signaturePacket:(PGPSignatureType)type hashAlgorithm:(PGPHashAlgorithm)hashAlgorithm;

+ (nullable NSData *)buildDataToSignForType:(PGPSignatureType)type inputData:(nullable NSData *)inputData key:(nullable PGPKey *)key subKey:(nullable PGPKey *)subKey keyPacket:(nullable PGPPublicKeyPacket *)signingKeyPacket userID:(nullable NSString *)userID error:(NSError *__autoreleasing _Nullable *)error;

- (nullable PGPMPI *)signatureMPI:(NSString *)identifier;

@end


NS_ASSUME_NONNULL_END
