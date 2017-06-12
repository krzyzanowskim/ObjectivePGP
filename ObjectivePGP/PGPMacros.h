//
//  PGPMacros.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 11/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#define let const __auto_type
#define var __auto_type

#define PGPAssertClass(object, allowedClass)                                                                                                                                                                                \
    do {                                                                                                                                                                                                                      \
        NSAssert([object isKindOfClass:[allowedClass class]], @"Object type not satisfying: '%@' must be of type '%s' but is '%@'.", object, #allowedClass, (object ? NSStringFromClass((Class)[object class]) : @"(null)")); \
    } while (0);

#define PGPNN(thing)                                              \
    ^{                                                              \
        __auto_type _Nonnull thang = thing;                         \
        NSCAssert(thang != nil, @"'" #thing "' Object must exist"); \
        return thang;                                               \
    }()

