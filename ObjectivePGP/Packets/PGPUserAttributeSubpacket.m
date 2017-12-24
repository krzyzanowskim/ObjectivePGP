//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPUserAttributeSubpacket.h"
#import "PGPMacros+Private.h"

NS_ASSUME_NONNULL_BEGIN

@implementation PGPUserAttributeSubpacket


#pragma mark - NSCopying

- (id)copyWithZone:(nullable NSZone * __unused)zone {
    let duplicate = [PGPUserAttributeSubpacket new];
    duplicate.type = self.type;
    duplicate.valueData = self.valueData;
    return duplicate;
}

@end

NS_ASSUME_NONNULL_END
