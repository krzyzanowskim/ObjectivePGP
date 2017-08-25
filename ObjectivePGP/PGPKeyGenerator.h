//
//  PGPKeyGenerator.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 25/08/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface PGPKeyGenerator : NSObject

- (NSData *)generateFor:(NSString *)userID;

@end

NS_ASSUME_NONNULL_END
