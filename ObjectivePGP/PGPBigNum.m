//
//  PGPBigNum.m
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 26/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPBigNum.h"
#import "PGPBigNum+Private.h"

@implementation PGPBigNum

- (int)bitsCount {
    return BN_num_bits(self.bignumRef);
}


- (int)bytesCount {
    return BN_num_bytes(self.bignumRef);
}

@end
