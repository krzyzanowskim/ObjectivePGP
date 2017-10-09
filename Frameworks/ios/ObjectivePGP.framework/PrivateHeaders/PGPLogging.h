//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#define PGPLogMacro(_level, _tag, _message) NSLog(@"[%s] %@ %s/%tu %@", _tag, @(_level), __PRETTY_FUNCTION__, __LINE__, _message())

#ifdef DEBUG
#define PGPLogDebug(format, ...)                                                     \
    PGPLogMacro(0, "ObjectivePGP", (^{                                               \
                    return [NSString stringWithFormat:(@"" format), ##__VA_ARGS__]; \
                }))
#else
#define PGPLogDebug(format, ...)
#endif

#define PGPLogWarning(format, ...)                                                   \
    PGPLogMacro(1, "ObjectivePGP", (^{                                               \
                    return [NSString stringWithFormat:(@"" format), ##__VA_ARGS__]; \
                }))
#define PGPLogError(format, ...)                                                     \
    PGPLogMacro(2, "ObjectivePGP", (^{                                               \
                    return [NSString stringWithFormat:(@"" format), ##__VA_ARGS__]; \
                }))

NS_ASSUME_NONNULL_END
