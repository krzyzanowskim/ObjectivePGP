//
//  PGPUser.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 30/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PGPUserIDPacket.h"

@interface PGPUser : NSObject
@property (strong, readonly) PGPUserIDPacket *packet;
@property (copy) NSString *userID;
@property (copy) NSArray *selfCertifications;  // me
@property (copy) NSArray *otherCertifications; // others

- (instancetype)initWithPacket:(PGPUserIDPacket *)packet NS_DESIGNATED_INITIALIZER;

@end
