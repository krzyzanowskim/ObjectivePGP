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

@property (assign, readonly) PGPPacketTag tag;

- (NSUInteger) headerLength;
- (UInt32) bodyLength;

- (instancetype) initWithHeader:(NSData *)headerData body:(NSData *)bodyData;
- (NSUInteger) parsePacketBody:(NSData *)packetBody;
@end


@interface PGPPacket : NSObject <PGPPacket>

@property (assign, readonly)    PGPPacketTag tag;
@property (assign) NSUInteger   headerLength;
@property (assign) UInt32       bodyLength;

+ (NSData *) parsePacketHeader:(NSData *)headerData bodyLength:(UInt32 *)bodyLength packetTag:(PGPPacketTag *)tag;

@end