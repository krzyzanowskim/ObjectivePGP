//
//  PGPParser.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 17/01/15.
//  Copyright (c) 2015 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface PGPParser : NSObject
- (BOOL) readStream:(NSInputStream *)inputStream error:(NSError * __autoreleasing *)error;
@end
