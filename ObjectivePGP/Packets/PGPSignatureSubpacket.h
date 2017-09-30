//
//  PGPSignatureSubPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPMacros.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPSignatureSubpacketHeader;

@interface PGPSignatureSubpacket : NSObject <NSCopying>

@property (nonatomic, readonly) PGPSignatureSubpacketType type;
@property (nonatomic, readonly, copy) id<NSObject, NSCopying> value;
@property (nonatomic, readonly) NSUInteger length;

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithType:(PGPSignatureSubpacketType)type andValue:(id<NSObject, NSCopying>)value NS_DESIGNATED_INITIALIZER;
- (instancetype)initWithHeader:(PGPSignatureSubpacketHeader *)header body:(NSData *)subPacketBodyData;

+ (PGPSignatureSubpacketHeader *)subpacketHeaderFromData:(NSData *)headerData;

- (void)parseSubpacketBody:(NSData *)packetBody;
- (nullable NSData *)export:(NSError *__autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
