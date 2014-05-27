//
//  PGPPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPPacket : NSObject

@property (copy, readonly) NSData *headerData;
@property (copy, readonly) NSData *bodyData;

@property (assign, readonly)    PGPPacketTag tag;

- (instancetype) initWithHeader:(NSData *)headerData body:(NSData *)bodyData;

+ (NSData *) parsePacketHeader:(NSData *)headerData bodyLength:(UInt32 *)bodyLength packetTag:(PGPPacketTag *)tag;
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error;

- (NSData *) exportPacket:(NSError *__autoreleasing *)error;

- (NSData *) buildHeaderData:(NSData *)bodyData;
+ (NSData *)buildNewFormatLengthDataForData:(NSData *)bodyData;

@end