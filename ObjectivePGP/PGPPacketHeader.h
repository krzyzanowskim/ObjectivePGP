//
//  PGPPacketHeader.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

typedef NS_ENUM(NSUInteger, PGPHeaderPacketTag) {
    PGPHeaderPacketTagNewFormat  = 0x40,
    PGPHeaderPacketTagAllwaysSet = 0x80
};

@protocol PGPPacketHeader <NSObject>
@property (assign, readonly) PGPPacketTag packetTag;
@property (assign, readonly) UInt8 headerLength;
@property (assign, readonly) UInt32 bodyLength;
@property (assign, readonly, getter=isBodyLengthPartial) BOOL bodyLengthPartial;
- (instancetype)initWithData:(NSData *)headerData error:(NSError * __autoreleasing *)error;
@end

@interface PGPPacketHeader : NSObject
+ (id <PGPPacketHeader> )packetHeaderWithData:(NSData *)headerData error:(NSError * __autoreleasing *)error;
@end
