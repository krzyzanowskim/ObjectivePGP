//
//  PGPSignatureSubPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTypes.h"
#import "PGPSignatureSubpacketHeader.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignatureSubpacket : NSObject

@property (nonatomic, readonly) NSRange bodyRange; // subrange range within parent packet

@property (nonatomic) PGPSignatureSubpacketType type;
@property (nonatomic, readonly) id value;

- (instancetype)initWithHeader:(PGPSignatureSubpacketHeader *)header body:(NSData *)subPacketBodyData bodyRange:(NSRange)bodyRange;
+ (PGPSignatureSubpacketHeader *)subpacketHeaderFromData:(NSData *)headerData;
+ (PGPSignatureSubpacket *)subpacketWithType:(PGPSignatureSubpacketType)type andValue:(id)value;

- (void)parseSubpacketBody:(NSData *)packetBody;
- (nullable NSData *)exportSubpacket:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
