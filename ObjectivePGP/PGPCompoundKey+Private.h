//
//  PGPCompoundKey+Private.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 10/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPCompoundKey.h"
#import "PGPKey.h"

NS_ASSUME_NONNULL_BEGIN

@interface PGPCompoundKey ()

@property (nonatomic, nullable, readwrite) PGPKey *secretKey;
@property (nonatomic, nullable, readwrite) PGPKey *publicKey;

@end

NS_ASSUME_NONNULL_END
