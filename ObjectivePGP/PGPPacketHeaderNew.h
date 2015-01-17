//
//  PGPPacketHeaderNew.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPacketHeader.h"
#import "PGPPacket.h"

@interface PGPPacketHeaderNew : PGPPacketHeader <PGPPacketHeader>
@property (assign, readonly) PGPPacketTag packetTag;
@property (assign, readonly) UInt8 headerLength;
@property (assign, readonly) UInt32 bodyLength;
@property (assign, readonly, getter=isBodyLengthPartial) BOOL bodyLengthPartial;
- (instancetype)initWithData:(NSData *)headerData error:(NSError * __autoreleasing *)error;
@end
