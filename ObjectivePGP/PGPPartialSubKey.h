//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPSignaturePacket;

@interface PGPPartialSubKey : PGPPartialKey <NSCopying>

PGP_EMPTY_INIT_UNAVAILABLE

- (instancetype)initWithPackets:(NSArray<PGPPacket *> *)packets __attribute__((unavailable("Not the designated initializer")));

- (instancetype)initWithPacket:(PGPPacket *)packet NS_DESIGNATED_INITIALIZER;

@property (nonatomic, nullable, copy, readonly) PGPSignaturePacket *bindingSignature;
@property (nonatomic, nullable, copy, readonly) PGPSignaturePacket *revocationSignature;

@property (nonatomic, readonly) PGPKeyID *keyID;

- (NSArray<PGPPacket *> *)allPackets;

@end

NS_ASSUME_NONNULL_END
