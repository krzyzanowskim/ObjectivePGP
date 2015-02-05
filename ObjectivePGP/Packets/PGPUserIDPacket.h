//
//  PGPUserIDPacket.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 19/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPUserIDPacket : NSObject
@property (copy) NSString *userID;

+ (instancetype) readFromStream:(NSInputStream *)inputStream maxLength:(NSUInteger)length error:(NSError * __autoreleasing *)error;
- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error;

@end
