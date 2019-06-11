//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPUserAttributeSubpacket.h"
#import "PGPMacros+Private.h"
#import "PGPFoundation.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPUserAttributeSubpacket


#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone * __unused)zone {
    let duplicate = [PGPUserAttributeSubpacket new];
    duplicate.type = self.type;
    duplicate.valueData = self.valueData;
    return duplicate;
}

#pragma mark - isEqual

- (BOOL)isEqual:(id)other {
    if (self == other) { return YES; }
    if ([other isKindOfClass:self.class]) {
        return [self isEqualToAttributeSubpacket:other];
    }
    return NO;
}

- (BOOL)isEqualToAttributeSubpacket:(PGPUserAttributeSubpacket *)packet {
    return self.type == packet.type && PGPEqualObjects(self.valueData, packet.valueData);
}

- (NSUInteger)hash {
    NSUInteger result = [super hash];
    result = 31 * self.type + self.valueData.hash;
    return result;
}

@end

NS_ASSUME_NONNULL_END
