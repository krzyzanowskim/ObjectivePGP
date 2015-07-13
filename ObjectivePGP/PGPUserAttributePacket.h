//
//  PGPUserAttributePacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 24/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacket.h"

@interface PGPUserAttributePacket : PGPPacket

// array of PGPUserAttributeSubpacket
@property (strong) NSArray *subpackets;

@end
