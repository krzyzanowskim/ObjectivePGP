//
//  Copyright (c) Marcin Krzyżanowski. All rights reserved.
//
//  THIS SOURCE CODE AND ANY ACCOMPANYING DOCUMENTATION ARE PROTECTED BY
//  INTERNATIONAL COPYRIGHT LAW. USAGE IS BOUND TO THE LICENSE AGREEMENT.
//  This notice may not be removed from this file.
//

#import <ObjectivePGP/PGPMacros.h>
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

NS_SWIFT_NAME(User) @interface PGPUser : NSObject <NSCopying>

@property (nonatomic, copy) NSString *userID;
@property (nonatomic, nullable) NSData *image;

PGP_EMPTY_INIT_UNAVAILABLE

@end

NS_ASSUME_NONNULL_END
