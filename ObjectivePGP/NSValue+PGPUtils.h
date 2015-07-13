//
//  NSValue+PGPUtils.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface NSValue (PGPUtils)

- (BOOL) pgp_objCTypeIsEqualTo:(const char *)type;

@end
