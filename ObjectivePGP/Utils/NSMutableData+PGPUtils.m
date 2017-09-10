//
//  NSMutableData+PGPUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/09/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "NSMutableData+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation NSMutableData (PGPUtils)

- (void)pgp_appendData:(nullable NSData *)other {
    if (other) {
        [self appendData:other];
    }
}

@end

NS_ASSUME_NONNULL_END
