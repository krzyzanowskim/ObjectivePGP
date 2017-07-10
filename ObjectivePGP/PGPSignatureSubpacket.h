//
//  PGPSignatureSubPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTypes.h"
#import "PGPMacros.h"
#import "PGPSignatureSubpacketHeader.h"
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPSignatureSubpacket : NSObject

@property (nonatomic, readonly) PGPSignatureSubpacketType type;
@property (nonatomic, readonly) id value;
@property (nonatomic, readonly) NSUInteger length;

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithType:(PGPSignatureSubpacketType)type andValue:(id)value NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithHeader:(PGPSignatureSubpacketHeader *)header body:(NSData *)subPacketBodyData;

+ (PGPSignatureSubpacketHeader *)subpacketHeaderFromData:(NSData *)headerData;

- (void)parseSubpacketBody:(NSData *)packetBody;
- (nullable NSData *)exportSubpacket:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
