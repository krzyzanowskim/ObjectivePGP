//
//  PGPUser.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 15/05/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@class PGPUserIDPacket;

@interface PGPUser : NSObject
@property (strong, nonatomic) NSString *userID;
@property (strong, nonatomic) NSArray *userAttribute; //TODO
@property (strong, nonatomic) NSArray *selfSignatures;
@property (strong, nonatomic) NSArray *otherSignatures;
@property (strong, nonatomic) NSArray *revocationSignatures;

- (instancetype) initWithPacket:(PGPUserIDPacket *)userPacket;

@end
