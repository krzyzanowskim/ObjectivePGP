//
//  NSArray+PGPUtils.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/09/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "NSArray+PGPUtils.h"

NS_ASSUME_NONNULL_BEGIN

@implementation NSMutableArray (PGPUtils)

- (void)pgp_addObject:(nullable id)anObject {
    if (anObject) {
        [self addObject:anObject];
    }
}

@end

@implementation NSArray (PGPUtils)

- (NSArray *)pgp_objectsPassingTest:(BOOL (^)(id obj, BOOL *stop))predicate {
    BOOL stop = NO;
    NSMutableArray *result = [NSMutableArray array];
    for (id object in self) {
        if (predicate(object,&stop)) {
            [result addObject:object];
        }
        if (stop) {
            break;
        }
    }
    return result;
}

@end

NS_ASSUME_NONNULL_END
