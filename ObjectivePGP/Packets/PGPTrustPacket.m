//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPTrustPacket.h"
#import "PGPMacros.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

@interface PGPTrustPacket ()

@property (nonatomic, copy, readwrite) NSData *data;

@end

@implementation PGPTrustPacket

- (PGPPacketTag)tag {
    return PGPTrustPacketTag;
}

- (NSUInteger)parsePacketBody:(NSData *)packetBody error:(NSError * __autoreleasing _Nullable *)error {
    NSUInteger position = [super parsePacketBody:packetBody error:error];

    // 5.10.  Trust Packet (Tag 12)
    // The format of Trust packets is defined by a given implementation.
    self.data = packetBody;
    position = position + self.data.length;
    return position;
}

- (nullable NSData *)export:(NSError * __autoreleasing _Nullable *)error {
    // Don't export trust packets
    // (1 octet "level" (depth), 1 octet of trust amount)
    return [self.data copy];
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([super isEqual:other] && [other isKindOfClass:self.class]) {
        return [self isEqualToTrustPacket:other];
    }
    return NO;
}

- (BOOL)isEqualToTrustPacket:(PGPTrustPacket *)packet {
    return PGPEqualObjects(self.data, packet.data);
}

- (NSUInteger)hash {
    NSUInteger prime = 31;
    NSUInteger result = [super hash];
    result = prime * result + self.data.hash;
    return result;
}

#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone *)zone {
    let _Nullable duplicate = PGPCast([super copyWithZone:zone], PGPTrustPacket);
    if (!duplicate) {
        return nil;
    }
    duplicate.data = self.data;
    return duplicate;
}


@end
