//
//  PGPSubKey.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 16/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPPacket.h"
#import "PGPSignaturePacket.h"

@interface PGPSubKey : NSObject

@property (strong, readonly) id <PGPPacket> packet;
@property (strong) PGPSignaturePacket *bindingSignature;
@property (strong) PGPSignaturePacket *revocationSignature;

- (instancetype) initWithPacket:(id <PGPPacket>)packet;

@end
