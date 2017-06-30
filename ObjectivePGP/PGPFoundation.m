//
//  PGPFoundation.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 31/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "ObjectivePGP.h"
#import "PGPMacros.h"

@implementation PGPFoundation

@end

OBJC_EXTERN inline id _pgp__cast(id obj, Class objClass) {
    NSCParameterAssert(objClass);
    return [obj isKindOfClass:objClass] ? obj : nil;
}
