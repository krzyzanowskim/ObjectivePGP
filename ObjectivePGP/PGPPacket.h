//
//  PGPPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 06/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"
#import "PGPExportableProtocol.h"

extern const UInt32 UnknownLength;

NS_ASSUME_NONNULL_BEGIN

@interface PGPPacket : NSObject <NSCopying, PGPExportable>

@property (nonatomic, copy, readonly) NSData *headerData;
@property (nonatomic, copy, readonly) NSData *bodyData;
@property (nonatomic) BOOL indeterminateLength; // should not be used, but gpg use it

@property (nonatomic, readonly) PGPPacketTag tag;
@property (nonatomic, readonly) NSData *packetData;

- (instancetype) init NS_DESIGNATED_INITIALIZER;
- (instancetype) initWithHeader:(NSData *)headerData body:(NSData *)bodyData;

+ (nullable NSData *) parsePacketHeader:(NSData*)data headerLength:(UInt32 *)headerLength nextPacketOffset:(nullable NSUInteger *)nextPacketOffset packetTag:(PGPPacketTag *)tag indeterminateLength:(BOOL*)indeterminateLength;
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError *__autoreleasing *)error;

- (NSData *) buildHeaderData:(NSData *)bodyData;
+ (NSData *) buildNewFormatLengthDataForData:(NSData *)bodyData;

@end

NS_ASSUME_NONNULL_END
