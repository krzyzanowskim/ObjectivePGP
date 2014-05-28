//
//  PGPSignatureSubPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPTypes.h"

@interface PGPSignatureSubpacketHeader : NSObject
@property (assign) PGPSignatureSubpacketType type;
@property (assign) NSUInteger headerLength;
@property (assign) NSUInteger bodyLength;
@end


@interface PGPSignatureSubpacket : NSObject

@property (assign, readonly) NSRange bodyRange; // subrange range within parent packet

@property (assign) PGPSignatureSubpacketType type;
@property (strong, readonly) id value;

- (instancetype) initWithHeader:(PGPSignatureSubpacketHeader *)header body:(NSData *)subPacketBodyData bodyRange:(NSRange)bodyRange;
+ (PGPSignatureSubpacketHeader *) subpacketHeaderFromData:(NSData *)headerData;
+ (PGPSignatureSubpacket *) subpacketWithType:(PGPSignatureSubpacketType)type andValue:(id)value;

- (void) parseSubpacketBody:(NSData *)packetBody;
- (NSData *) exportSubpacket:(NSError *__autoreleasing *)error;

@end
