//
//  PGPBigNum.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPBigNum : NSObject

@property (nonatomic, readonly) int bitsCount;
@property (nonatomic, readonly) int bytesCount;

@end
