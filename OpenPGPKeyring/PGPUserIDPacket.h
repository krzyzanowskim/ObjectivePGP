//
//  PGPUserID.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 05/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 13

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPUserIDPacket : NSObject <PGPPacket>

@property (assign, readonly, nonatomic) PGPPacketTag tag;
@property (retain, readonly) NSString *userID;

- (instancetype) initWithBody:(NSData *)packetData;
- (void) parsePacketBody:(NSData *)packetBody;

@end
