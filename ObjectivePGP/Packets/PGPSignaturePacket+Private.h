//
//  PGPSignaturePacket+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/07/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

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
