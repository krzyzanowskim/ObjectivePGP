//
//  PGPTransferableKey.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 13/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPTransferableKey.h"

@implementation PGPTransferableKey

- (NSArray *)revocationSignatures
{
    if (!_revocationSignatures) {
        _revocationSignatures = [NSArray array];
    }
    return _revocationSignatures;
}

@end
