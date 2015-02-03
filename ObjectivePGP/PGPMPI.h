//
//  PGPMPI.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 18/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPMPI : NSObject
@property (copy) NSString *identifier; // descriptive identifier like P, G, Y, etc...
@property (copy) NSData *data;

+ (instancetype) readFromStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;
- (BOOL) writeToStream:(NSOutputStream *)outputStream error:(NSError * __autoreleasing *)error;

//- (NSData *) buildMPIData:(NSError * __autoreleasing *)error;

@end
