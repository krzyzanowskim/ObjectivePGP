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

- (nullable NSData *)buildDataToSignForType:(PGPSignatureType)type inputData:(nullable NSData *)inputData key:(nullable PGPPartialKey *)key keyPacket:(nullable PGPPublicKeyPacket *)keyPacket userID:(nullable NSString *)userID error:(NSError *__autoreleasing _Nullable *)error;

@end


NS_ASSUME_NONNULL_END
