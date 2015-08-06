//
//  PGPPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

extern const UInt32 UnknownLength;

@interface PGPPacket : NSObject <NSCopying>

@property (copy, readonly) NSData *headerData;
@property (copy, readonly) NSData *bodyData;
@property (assign) BOOL indeterminateLength; // should not be used, but gpg use it

@property (assign, readonly)    PGPPacketTag tag;
@property (readonly)    NSData *packetData;

- (instancetype) init NS_DESIGNATED_INITIALIZER;
- (instancetype) initWithHeader:(NSData *)headerData body:(NSData *)bodyData;

+ (NSData *) parsePacketHeader:(NSData*)data headerLength:(UInt32 *)headerLength nextPacketOffset:(NSUInteger *)nextPacketOffset packetTag:(PGPPacketTag *)tag indeterminateLength:(BOOL*)indeterminateLength;
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error;

- (NSData *) exportPacket:(NSError *__autoreleasing *)error;

- (NSData *) buildHeaderData:(NSData *)bodyData;
+ (NSData *) buildNewFormatLengthDataForData:(NSData *)bodyData;

@end