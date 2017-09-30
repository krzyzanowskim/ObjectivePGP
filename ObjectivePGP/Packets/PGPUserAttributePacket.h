//
//  PGPUserAttributePacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"
#import "PGPUserAttributeSubpacket.h"

@interface PGPUserAttributePacket : PGPPacket <NSCopying>

// array of PGPUserAttributeSubpacket
@property (nonatomic) NSArray<PGPUserAttributeSubpacket *> *subpackets;

@end
