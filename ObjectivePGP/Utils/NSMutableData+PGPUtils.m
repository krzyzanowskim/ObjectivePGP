//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "NSMutableData+PGPUtils.h"
#import "PGPMacros.h"

NS_ASSUME_NONNULL_BEGIN

@implementation NSMutableData (PGPUtils)

- (void)pgp_appendData:(nullable NSData *)other {
    if (other) {
        [self appendData:PGPNN(other)];
    }
}

@end

NS_ASSUME_NONNULL_END
