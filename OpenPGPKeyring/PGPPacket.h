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

- (NSData *) headerData;
- (NSData *) bodyData;

- (instancetype) initWithHeader:(NSData *)headerData body:(NSData *)bodyData;
- (NSUInteger) parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error;
@end


@interface PGPPacket : NSObject <PGPPacket>

@property (copy, readonly) NSData *headerData;
@property (copy, readonly) NSData *bodyData;

@property (assign, readonly)    PGPPacketTag tag;

+ (NSData *) parsePacketHeader:(NSData *)headerData bodyLength:(UInt32 *)bodyLength packetTag:(PGPPacketTag *)tag;

@end