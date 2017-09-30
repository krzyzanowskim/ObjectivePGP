//
//  PGPKey+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPKey.h"
#import "PGPPartialKey.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPKey ()

@property (nonatomic, nullable, copy, readwrite) PGPPartialKey *secretKey;
@property (nonatomic, nullable, copy, readwrite) PGPPartialKey *publicKey;

@end

NS_ASSUME_NONNULL_END
