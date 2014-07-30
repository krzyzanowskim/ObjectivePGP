//
//  PGPTrustPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 12

#import <Foundation/Foundation.h>
#import "PGPPacketFactory.h"

@interface PGPTrustPacket : PGPPacket

@property (strong, readonly) NSData *data;


@end
