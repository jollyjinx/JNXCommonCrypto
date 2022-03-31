//
//  NSData+randomGenerator.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-20.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSData (randomGenerator)

+ (NSData *)randomIV;
+ (size_t)randomIVLength;
+ (NSData *)randomSalt;
+ (size_t)randomSaltLength;
+ (NSData *)randomDataWithLength:(size_t)length;
@end
