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

- (void)XORWithData:(NSData *)data index:(NSUInteger)index {
    uint8_t *dataPtr = (uint8_t *)self.mutableBytes;
    const uint8_t *data2Ptr = (uint8_t *)data.bytes;

    NSAssert(index < self.length, @"Invalid index");

    for (NSUInteger i = 0; i < data.length && (i + index) < self.length; i++) {
        dataPtr[i + index] = dataPtr[i + index] ^ data2Ptr[i];
    }
}

@end

NS_ASSUME_NONNULL_END
