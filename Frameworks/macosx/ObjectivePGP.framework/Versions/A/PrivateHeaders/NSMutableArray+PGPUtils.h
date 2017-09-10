//
//  NSMutableArray+PGPUtils.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/09/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface NSMutableArray <ObjectType> (PGPUtils)

- (void)pgp_addObject:(nullable ObjectType)anObject;

@end

NS_ASSUME_NONNULL_END
