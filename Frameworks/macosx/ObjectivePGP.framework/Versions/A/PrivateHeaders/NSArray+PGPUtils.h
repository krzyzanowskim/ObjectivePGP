//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSMutableArray <ObjectType> (PGPUtils)

- (void)pgp_addObject:(nullable ObjectType)anObject;

@end

@interface NSArray <ObjectType> (PGPUtils)

- (NSArray<ObjectType> *)pgp_objectsPassingTest:(BOOL (^)(ObjectType obj, BOOL *stop))predicate;

@end

NS_ASSUME_NONNULL_END
