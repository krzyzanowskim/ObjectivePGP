//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import "PGPMacros.h"

#define let const __auto_type
#define var __auto_type

#define pgpweakify(var) __weak typeof(var) PGPWeak_##var = var;

#define pgpstrongify(var) \
    _Pragma("clang diagnostic push") \
    _Pragma("clang diagnostic ignored \"-Wshadow\"") \
    __strong typeof(var) var = PGPWeak_##var; \
    _Pragma("clang diagnostic pop")

#define PGP_CLASS_EXPORT __attribute__((visibility("default")))

#define PGP_EMPTY_INIT_UNAVAILABLE                                                      \
    -(instancetype)init __attribute__((unavailable("Not the designated initializer"))); \
    +(instancetype)new __attribute__((unavailable("Not the designated initializer")));

#define PGPAssertClass(object, allowedClass)                                                                                                                                                                                  \
    do {                                                                                                                                                                                                                      \
        NSAssert([object isKindOfClass:[allowedClass class]], @"Object type not satisfying: '%@' must be of type '%s' but is '%@'.", object, #allowedClass, (object ? NSStringFromClass((Class)[object class]) : @"(null)")); \
    } while (0);

#define PGPNN(thing)                                                \
    ^{                                                              \
        __auto_type _Nonnull thang = thing;                         \
        NSCAssert(thang != nil, @"'" #thing "' Object must exist"); \
        return thang;                                               \
    }()

// Similar to defer in Swift
#define pgp_defer_block_name_with_prefix(prefix, suffix) prefix##suffix
#define pgp_defer_block_name(suffix) pgp_defer_block_name_with_prefix(pgp_defer_, suffix)
#define pgp_defer __strong void (^pgp_defer_block_name(__LINE__))(void) __attribute__((cleanup(pgp_defer_cleanup_block), unused)) = ^
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
static void pgp_defer_cleanup_block(__strong void (^ _Nonnull * _Nonnull block)(void)) { (*block)(); }
#pragma clang diagnostic pop

#define PGPDataAppendPropertyBytes(d,var,len) \
    [d appendBytes:&self->_##var length:len]

