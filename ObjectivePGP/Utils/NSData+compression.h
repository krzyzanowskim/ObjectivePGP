//
//  NSData+zlib.h
//
// rfc1950 (zlib format)

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const ZlibErrorDomain;

@interface NSData (compression)

- (NSData *)zlibCompressed:(NSError *__autoreleasing _Nullable *)error;
- (NSData *)zlibDecompressed:(NSError *__autoreleasing _Nullable *)error compressionType:(int)compressionType;

- (NSData *)bzip2Decompressed:(NSError *__autoreleasing *)error;
- (NSData *)bzip2Compressed:(NSError *__autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
