//
//  PGPLogging.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 14/05/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
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
