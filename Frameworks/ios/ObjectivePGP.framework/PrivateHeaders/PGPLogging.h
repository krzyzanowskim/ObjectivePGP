//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

#define PGP_NO_LOG          0x00
#define PGP_ERROR_LEVEL     0x01
#define PGP_WARNING_LEVEL   0x02
#define PGP_DEBUG_LEVEL     0x03

#ifndef PGP_LOG_LEVEL
    #ifdef DEBUG
        #define PGP_LOG_LEVEL PGP_DEBUG_LEVEL
    #else
        #define PGP_LOG_LEVEL PGP_WARNING_LEVEL
    #endif
#endif

#define _PGPLogMacro(_level, _tag, _message) NSLog(@"[%s] %s: %s/%tu %@", _tag, _level, __PRETTY_FUNCTION__, __LINE__, _message())

#if PGP_LOG_LEVEL >= PGP_DEBUG_LEVEL
#define PGPLogDebug(format, ...)                                                     \
    _PGPLogMacro("DEBUG", "ObjectivePGP", (^{                                               \
                    return [NSString stringWithFormat:(@"" format), ##__VA_ARGS__]; \
                }))
#else
#define PGPLogDebug(format, ...)
#endif

#if PGP_LOG_LEVEL >= PGP_WARNING_LEVEL
#define PGPLogWarning(format, ...)                                                   \
    _PGPLogMacro("WARNING", "ObjectivePGP", (^{                                               \
                    return [NSString stringWithFormat:(@"" format), ##__VA_ARGS__]; \
                }))
#else
#define PGPLogWarning(format, ...)
#endif

#if PGP_LOG_LEVEL >= PGP_ERROR_LEVEL
#define PGPLogError(format, ...)                                                     \
    _PGPLogMacro("ERROR", "ObjectivePGP", (^{                                               \
                    return [NSString stringWithFormat:(@"" format), ##__VA_ARGS__]; \
                }))
#else
#define PGPLogError(format, ...)
#endif

NS_ASSUME_NONNULL_END
