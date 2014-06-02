//
//  NSData+IDZGunzip
//
// Copyright (c) 2013 iOSDeveloperZone.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
#import "NSData+IDZGunzip.h"
#import <zlib.h>

NSString* const IDZGunzipErrorDomain = @"com.iosdeveloperzone.IDZGunzip";

@implementation NSData (IDZGunzip)

- (NSData*)gunzip:(NSError *__autoreleasing *)error
{
    /*
     * A minimal gzip header/trailer is 18 bytes long.
     * See: RFC 1952 http://www.gzip.org/zlib/rfc-gzip.html
     */
    if(self.length < 18)
    {
        if(error)
            *error = [NSError errorWithDomain:IDZGunzipErrorDomain code:Z_DATA_ERROR userInfo:nil];
        return nil;
    }
    z_stream zStream;
    memset(&zStream, 0, sizeof(zStream));
    /* 
     * 16 is a magic number that allows inflate to handle gzip 
     * headers.
     */
    int iResult = inflateInit2(&zStream, 16);
    if(iResult != Z_OK)
    {
        if(error)
            *error = [NSError errorWithDomain:IDZGunzipErrorDomain code:iResult userInfo:nil];
        return nil;
    }
    /*
     * The last four bytes of a gzipped file/buffer contain the the number 
     * of uncompressed bytes expressed as a 32-bit little endian unsigned integer.
     * See: RFC 1952 http://www.gzip.org/zlib/rfc-gzip.html
     */
    UInt32 nUncompressedBytes = *(UInt32*)(self.bytes + self.length - 4);
    NSMutableData* gunzippedData = [NSMutableData dataWithLength:nUncompressedBytes];
    
    zStream.next_in = (Bytef*)self.bytes;
    zStream.avail_in = self.length;
    zStream.next_out = (Bytef*)gunzippedData.bytes;
    zStream.avail_out = gunzippedData.length;
    
    iResult = inflate(&zStream, Z_FINISH);
    if(iResult != Z_STREAM_END)
    {
        if(error)
            *error = [NSError errorWithDomain:IDZGunzipErrorDomain code:iResult userInfo:nil];
        gunzippedData = nil;
    }
    inflateEnd(&zStream);
    return gunzippedData;
}

@end
