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
- (NSArray *)pgp_flatMap:(NS_NOESCAPE NSArray *_Nullable (^)(ObjectType obj))block;

@end

@interface NSArray <ObjectType> (PGPUtils)

- (NSArray<ObjectType> *)pgp_objectsPassingTest:(NS_NOESCAPE BOOL (^)(ObjectType obj, BOOL *stop))predicate;
- (NSArray *)pgp_flatMap:(NS_NOESCAPE NSArray *_Nullable (^)(ObjectType obj))block;

@end

NS_ASSUME_NONNULL_END
