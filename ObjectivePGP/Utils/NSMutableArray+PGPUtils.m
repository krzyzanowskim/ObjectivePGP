//
//  NSMutableArray+PGPUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/09/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "NSMutableArray+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation NSMutableArray (PGPUtils)

- (void)pgp_addObject:(nullable id)anObject {
    if (anObject) {
        [self addObject:anObject];
    }
}

@end

NS_ASSUME_NONNULL_END
