//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPUserAttributePacket.h"
#import "PGPUserAttributeSubpacket.h"
#import "PGPUserAttributeImageSubpacket.h"
#import "PGPPacketHeader.h"
#import "PGPFoundation.h"
#import "PGPMacros+Private.h"
#import "PGPLogging.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPUserAttributePacket

- (instancetype)init {
    if ((self = [super init])) {
        _subpackets = [NSArray<PGPUserAttributeSubpacket *> array];
    }
    return self;
}

- (PGPPacketTag)tag {
    return PGPUserAttributePacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    const NSUInteger startPosition = [super parsePacketBody:packetBody error:error];
    NSUInteger position = startPosition;

    // read subpackets
    while (position < packetBody.length) {
        UInt32 bodyLength = 0;
        UInt8 lengthBytesCount = 0;
        let subPacketData = [packetBody subdataWithRange:(NSRange){position, packetBody.length - position}];
        [PGPPacketHeader getLengthFromNewFormatOctets:subPacketData bodyLength:&bodyLength bytesCount:&lengthBytesCount isPartial:nil];
        position = position + lengthBytesCount;

        PGPUserAttributeSubpacketType subpacketType = 0;
        [subPacketData getBytes:&subpacketType range:(NSRange){position, 1}];
        position = position + 1;

        // the subpacket type is part of body
        let subPacketBodyData = [subPacketData subdataWithRange:(NSRange){position, bodyLength - 1}];

        switch (subpacketType) {
            case PGPUserAttributeSubpacketImage: {
                let subpacket = [[PGPUserAttributeImageSubpacket alloc] init];
                subpacket.type = subpacketType;
                subpacket.valueData = subPacketBodyData;
                self.subpackets = [self.subpackets arrayByAddingObject:subpacket];
            } break;
            default:
                // Ignore everything else
                break;
        }

        position = position + subPacketBodyData.length;
    }

    return position;
}

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    // TODO: export
    PGPLogDebug(@"Exporting %@ not implemented", NSStringFromClass(self.class));
    return nil;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToAttributePacket:other];
    }
    return NO;
}

- (BOOL)isEqualToAttributePacket:(PGPUserAttributePacket *)packet {
    return PGPEqualObjects(self.subpackets,packet.subpackets);
}

- (NSUInteger)hash {
    NSUInteger result = [super hash];
    result = 31 * result + self.subpackets.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let _Nullable duplicate = PGPCast([super copyWithZone:zone], PGPUserAttributePacket);
    if (!duplicate) {
        return nil;
    }
    duplicate.subpackets = [[NSArray alloc] initWithArray:self.subpackets copyItems:YES];
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
