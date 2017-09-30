//
//  PGPPartialSubKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPSignaturePacket;

@interface PGPPartialSubKey : PGPPartialKey <NSCopying>

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets __attribute__((unavailable("Not the designated initializer")));

- (instancetype)initWithPacket:(PGPPacket *)packet NS_DESIGNATED_INITIALIZER;

@property (nonatomic, nullable, readonly) PGPSignaturePacket *bindingSignature;
@property (nonatomic, nullable, readonly) PGPSignaturePacket *revocationSignature;

@property (nonatomic, readonly) PGPKeyID *keyID;

- (NSArray<PGPPacket *> *)allPackets;

@end

NS_ASSUME_NONNULL_END
