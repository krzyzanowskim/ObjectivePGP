//
//  NSData+zlib.h
//
// rfc1950 (zlib format)

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString *const ZlibErrorDomain;

@interface NSData (compression)

- (nullable NSData *)zipCompressed:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)zlibCompressed:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)zipDecompressed:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)zlibDecompressed:(NSError * __autoreleasing _Nullable *)error;

- (nullable NSData *)bzip2Decompressed:(NSError * __autoreleasing _Nullable *)error;
- (nullable NSData *)bzip2Compressed:(NSError * __autoreleasing _Nullable *)error;

@end

NS_ASSUME_NONNULL_END
