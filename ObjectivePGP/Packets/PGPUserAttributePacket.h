//
//  PGPUserAttributePacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

NS_ASSUME_NONNULL_BEGIN

@class PGPUserAttributeSubpacket;

@interface PGPUserAttributePacket : PGPPacket <NSCopying>

// array of PGPUserAttributeSubpacket
@property (nonatomic) NSArray<PGPUserAttributeSubpacket *> *subpackets;

@end

NS_ASSUME_NONNULL_END
