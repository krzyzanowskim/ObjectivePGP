//
//  main.m
//  opgp
//
//  Created by Marcin Krzyzanowski on 24/06/14.
//  Copyright (c) 2014 Marcin Krzyżanowski. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "ObjectivePGP.h"

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        NSUserDefaults *standardDefaults = [NSUserDefaults standardUserDefaults];
        
        [standardDefaults registerDefaults:@{@"armor":@(YES)}];
        
        NSString *inputPath = [standardDefaults stringForKey:@"input"];
        NSString *messagePlaintext = [standardDefaults stringForKey:@"msg"];
        NSString *outputFile = [standardDefaults stringForKey:@"output"];
        NSString *pubringFile = [standardDefaults stringForKey:@"pubring"];
        NSString *secringFile = [standardDefaults stringForKey:@"secring"];
        NSString *keyIdentifier = [standardDefaults stringForKey:@"keyid"];
        NSString *keyFile = [standardDefaults stringForKey:@"key"];
        NSString *passprase = [standardDefaults stringForKey:@"passphrase"];
        BOOL armor = [standardDefaults boolForKey:@"armor"];

        if (outputFile) {
            fprintf(stdout, "opgp (ObjectivePGP) 0.0.2 (alpha)\n");
            fprintf(stdout, "Copyright (C) 2014 Marcin Krzyżanowski <marcin.krzyzanowski@hakore.com>\n");
            fprintf(stdout, "All rights reserved. No warranty, explicit or implicit, provided.\n");
        }

        NSArray *commandLineArguments = [[NSProcessInfo processInfo] arguments];
        if (commandLineArguments.count == 1 || [commandLineArguments containsObject:@"-help"]) {
            fprintf(stdout, "\n");
            fprintf(stdout, "Usage: opgp [-encrypt] [-key keyfile.asc] [-armor 1] [-msg \"message\"] ...\n");
            fprintf(stdout, "Options:\n");
            fprintf(stdout, "\t-decrypt     Decrypt mode (Default)\n");
            fprintf(stdout, "\t-encrypt     Encrypt mode \n");
            fprintf(stdout, "\t-input       file.txt - path or URL to input file\n");
            fprintf(stdout, "\t-msg         \"message\" - input text\n");
            fprintf(stdout, "\t-keyid       [28A83333F9C27197|F9C27197] - public or secret key identifier (Optional if \"-key\" is specified)\n");
            fprintf(stdout, "\t-key         key.asc - public or secret key file\n");
            fprintf(stdout, "\t-output      file.txt.gpg - output path (Optional)\n");
            fprintf(stdout, "\t-pubring     [pubring.gpg|pubring.asc] - keyring with public keys (Optional)\n");
            fprintf(stdout, "\t-secring     [secring.gpg|secring.asc] - keyring with public keys (Optional)\n");
            fprintf(stdout, "\t-passphrase  12345 - secret key password (Optional)\n");
            fprintf(stdout, "\t-armor       [1|0] - output format (Optional)\n");
            fprintf(stdout, "\t-help        Help\n");
            fprintf(stdout, "\t-license     License\n");
            return 0;
        }
        
        if ([commandLineArguments containsObject:@"-license"]) {
            fprintf(stdout, "You are granted a non-exclusive License to use the Software for any purposes for an unlimited period of time.\n\
The software product under this License is provided free of charge.\n\
Even though a license fee is not paid for the use of Freeware Version software,\n\
it does not mean that there are no conditions for using such software:\n\n\
- The Software may be installed and used by the Licensee for any legal purpose.\n\
- The Software may be installed and used by the Licensee on any number of systems.\n\
- The Software can be copied and distributed under the condition that original copyright notice\n\
  and disclaimer of warranty will stay intact, and the Licensee will not charge money\n\
  or fees for the Software product, except to cover distribution costs.\n\
- The Licensee will not have any proprietary rights in and to the Software.\n\
- The Licensee acknowledges and agrees that the Licensor retains all copyrights\n\
  and other proprietary rights in and to the Software.\n\n\
Use within the scope of this License is free of charge and no royalty or licensing fees shall be paid by the Licensee.\n\n");
            return 0;
        }
        
        BOOL encrypt = NO;
        if ([commandLineArguments containsObject:@"-encrypt"]) {
            encrypt = YES;
        }
        
        if (!pubringFile) {
            pubringFile = [[NSHomeDirectory() stringByAppendingPathComponent:@".gnupg"] stringByAppendingPathComponent:@"pubring.gpg"];
        }

        if (!secringFile) {
            secringFile = [[NSHomeDirectory() stringByAppendingPathComponent:@".gnupg"] stringByAppendingPathComponent:@"secring.gpg"];
        }
        
        // load or fetch input file
        NSData *inputData = nil;
        if (messagePlaintext) {
            inputData = [messagePlaintext dataUsingEncoding:NSUTF8StringEncoding];
        } else {
            NSURL *inputURL = [NSURL URLWithString:inputPath];
            if (inputURL.scheme) {
                NSError *loadURLError = nil;
                inputData = [NSData dataWithContentsOfURL:inputURL options:NSDataReadingMappedIfSafe error:&loadURLError];
                if (loadURLError) {
                    fprintf(stderr, "ERROR: Unable to fetch %s\n", inputPath.UTF8String);
                    return 1;
                }
            } else {
                inputData = [NSData dataWithContentsOfMappedFile:inputPath];
            }
        }
        
        if (!inputData) {
            fprintf(stderr, "ERROR: Invalid input data\n");
            return 1;
        }

        // Build output filename
        if (!outputFile) {
            NSString *extension = armor ? @"asc" : @"gpg";
            if (inputPath) {
                outputFile = [[inputPath lastPathComponent] stringByAppendingPathExtension:extension];
            }
        }
        
        ObjectivePGP *pgp = [[ObjectivePGP alloc] init];
        
        if (pubringFile) {
            [pgp importKeysFromFile:[pubringFile stringByExpandingTildeInPath]];
        }
        
        if (secringFile) {
            [pgp importKeysFromFile:[secringFile stringByExpandingTildeInPath]];
        }
        
        // load key
        PGPKey *operationKey = nil;
        if (keyFile) {
            NSData *fetchedKeyData = nil;
            NSURL *keyURL = [NSURL URLWithString:keyFile];
            if (keyURL.scheme) {
                NSError *loadURLError = nil;
                fetchedKeyData = [NSData dataWithContentsOfURL:keyURL options:NSDataReadingMappedIfSafe error:&loadURLError];
                if (loadURLError) {
                    fprintf(stderr, "ERROR: Unable to fetch key at %s\n", keyFile.UTF8String);
                    return 1;
                }
            } else {
                fetchedKeyData = [NSData dataWithContentsOfMappedFile:[keyFile stringByExpandingTildeInPath]];
            }

            NSArray *loadedKeys = [pgp importKeysFromData:fetchedKeyData];
            if (!keyIdentifier) {
                PGPKey *key = [loadedKeys firstObject];
                operationKey = key;
            }
        }

        if (keyIdentifier) {
            if (encrypt) {
                operationKey = [pgp getKeyForIdentifier:keyIdentifier type:PGPKeyPublic];
            } else {
                operationKey = [pgp getKeyForIdentifier:keyIdentifier type:PGPKeySecret];
            }
            
            if (!operationKey) {
                fprintf(stderr, "ERROR: Can't use key %s\n", keyIdentifier.UTF8String);
                return 1;
            }
        }
        
        NSData *outputData = nil;
        NSError *operationError = nil;
        if (encrypt) {
            outputData = [pgp encryptData:inputData usingPublicKey:operationKey armored:armor error:&operationError];
        } else {
            outputData = [pgp decryptData:inputData passphrase:passprase error:&operationError];
        }
        
        if (operationError) {
            fprintf(stderr, "ERROR: %s\n", operationError.localizedDescription.UTF8String);
        } else {
            if (outputFile) {
                if (![outputData writeToFile:[outputFile stringByExpandingTildeInPath] atomically:YES]) {
                    fprintf(stderr, "ERROR: Can't write to output file\n");
                    return 1;
                }
                fprintf(stdout, "Written to %s\n", outputFile.UTF8String);
            } else {
                fwrite(outputData.bytes, outputData.length, 1, stdout);
            }
        }
    }
    return 0;
}
