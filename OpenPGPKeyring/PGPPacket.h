//
//  PGPPacket.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@protocol PGPPacket <NSObject>

@required

- (PGPPacketTag) tag;
- (NSUInteger) headerLength;
- (UInt32) bodyLength;

- (void) parsePacketBody:(NSData *)packetBody;
@end


@interface PGPPacket : NSObject <PGPPacket>

@property (assign) PGPPacketTag tag;
@property (assign) NSUInteger   headerLength;
@property (assign) UInt32       bodyLength;

- (instancetype) initWithHeaderData:(NSData *)headerData;
- (BOOL) parsePacketHeader:(NSData *)headerData;

@end