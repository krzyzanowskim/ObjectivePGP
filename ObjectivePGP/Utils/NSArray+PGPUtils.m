//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
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
