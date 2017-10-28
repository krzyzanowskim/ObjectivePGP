//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPTypes.h>
#import <ObjectivePGP/PGPMacros.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@class PGPSignatureSubpacketHeader;

@interface PGPSignatureSubpacket : NSObject <NSCopying>

@property (nonatomic, readonly) PGPSignatureSubpacketType type;
@property (nonatomic, readonly, nullable, copy) id<NSObject, NSCopying> value;
@property (nonatomic, readonly) NSUInteger length;

PGP_EMPTY_INIT_UNAVAILABLE;

- (instancetype)initWithType:(PGPSignatureSubpacketType)type andValue:(nullable id<NSObject, NSCopying>)value NS_DESIGNATED_INITIALIZER;
- (nullable instancetype)initWithHeader:(PGPSignatureSubpacketHeader *)header body:(NSData *)subPacketBodyData;

+ (PGPSignatureSubpacketHeader *)subpacketHeaderFromData:(NSData *)headerData;

- (void)parseSubpacketBody:(NSData *)packetBody;
- (nullable NSData *)export:(NSError *__autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
