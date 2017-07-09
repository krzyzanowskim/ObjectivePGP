//
//  PGPSubKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKeyID.h"
#import "PGPPacket.h"
#import "PGPPartialKey.h"
#import "PGPSignaturePacket.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPSubKey : PGPPartialKey

PGP_EMPTY_INIT_UNAVAILABLE

@property (nonatomic, nullable) PGPSignaturePacket *bindingSignature;
@property (nonatomic, readonly) PGPKeyID *keyID;

- (NSArray<PGPPacket *> *)allPackets;

@end

NS_ASSUME_NONNULL_END
