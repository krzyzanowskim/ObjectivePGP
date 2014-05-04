//
//  PGPSignature.h
//  OpenPGPKeyring
//
//  Created by Marcin Krzyzanowski on 04/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//
//  Tag 2

#import <Foundation/Foundation.h>
#import "PGPPacket.h"

@interface PGPSignature : NSObject <PGPPacket>

- (instancetype) initWithBody:(NSData *)packetData;

@end
