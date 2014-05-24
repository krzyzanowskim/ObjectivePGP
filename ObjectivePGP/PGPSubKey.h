//
//  PGPSubKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPKey.h"
#import "PGPPacket.h"
#import "PGPSignaturePacket.h"

@interface PGPSubKey : NSObject

@property (strong, readonly) PGPPacket * keyPacket;
@property (strong) PGPSignaturePacket *bindingSignature;
@property (strong, nonatomic) PGPSignaturePacket *revocationSignature;

- (instancetype) initWithPacket:(PGPPacket *)packet;
- (NSArray *) allPackets;

@end
