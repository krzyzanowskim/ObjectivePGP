//
//  PGPExportableProtocol.h
//  ObjectivePGP
//
//  Created by Marcin Krzyzanowski on 11/06/2017.
//  Copyright © 2017 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol PGPExportable <NSObject>

- (nullable NSData *)export:(NSError *_Nullable __autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
