//
//  PGPPublicSubKey.m
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import "PGPPublicSubKey.h"

@implementation PGPPublicSubKey

- (PGPPacketTag)tag
{
    return PGPPublicSubkeyPacketTag;
}

@end
