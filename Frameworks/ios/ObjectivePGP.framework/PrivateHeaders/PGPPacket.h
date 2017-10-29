//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPExportableProtocol.h>
#import <ObjectivePGP/PGPTypes.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern const UInt32 PGPUnknownLength;

@interface PGPPacket : NSObject <NSCopying, PGPExportable>

@property (nonatomic, readonly) PGPPacketTag tag;

- (instancetype)init NS_DESIGNATED_INITIALIZER;
+ (nullable instancetype)packetWithBody:(NSData *)bodyData;

+ (nullable NSData *)parsePacketHeader:(NSData *)data headerLength:(UInt32 *)headerLength nextPacketOffset:(nullable NSUInteger *)nextPacketOffset packetTag:(PGPPacketTag *)tag indeterminateLength:(BOOL *)indeterminateLength;
- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error;

+ (NSData *)buildPacketOfType:(PGPPacketTag)tag withBody:(PGP_NOESCAPE NSData *(^)(void))body;

- (id)copyWithZone:(nullable NSZone *)zone NS_REQUIRES_SUPER;

@end

NS_ASSUME_NONNULL_END
