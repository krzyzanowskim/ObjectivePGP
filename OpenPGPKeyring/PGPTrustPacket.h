//
//  PGPTrustPacket.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 12

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPTrustPacket : NSObject <PGPPacket>

@property (assign, readonly, nonatomic) PGPPacketTag tag;
@property (strong, readonly) NSData *data;

- (instancetype) initWithBody:(NSData *)packetData;
- (void) parsePacketBody:(NSData *)packetBody;

@end
