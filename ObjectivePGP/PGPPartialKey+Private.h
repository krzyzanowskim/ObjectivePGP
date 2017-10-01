//
//  PGPPartialKey+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 30/09/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/ObjectivePGP.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPPartialKey ()

@property (nonatomic, readwrite) PGPPartialKeyType type;
@property (nonatomic, nullable, copy, readwrite) NSArray<PGPSignaturePacket *> *directSignatures;
@property (nonatomic, nullable, copy, readwrite) PGPSignaturePacket *revocationSignature;

- (void)loadPackets:(NSArray<PGPPacket *> *)packets NS_REQUIRES_SUPER;

@end

NS_ASSUME_NONNULL_END
