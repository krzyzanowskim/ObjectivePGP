//
//  PGPPartialSubKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKeyID.h"
#import "PGPPartialKey.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPSignaturePacket;

@interface PGPPartialSubKey : PGPPartialKey

PGP_EMPTY_INIT_UNAVAILABLE

@property (nonatomic, nullable) PGPSignaturePacket *bindingSignature;
@property (nonatomic, readonly) PGPKeyID *keyID;

- (NSArray<PGPPacket *> *)allPackets;

@end

NS_ASSUME_NONNULL_END
