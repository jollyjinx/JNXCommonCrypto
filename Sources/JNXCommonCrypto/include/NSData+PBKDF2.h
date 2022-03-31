//
//  NSData+PBKDF2.h
//  Keychain2Go
//
//  Created by Stein Patrick on 11-08-20.
//  Copyright (c) 2011 jinx.eu. All rights reserved.
//

@import Foundation;

@interface NSString (PBKDF2)

- (NSData *)pbkdf2hashPasswordWithSalt:(NSData *)saltData;
- (NSData *)pbkdf2hashPasswordWithSalt:(NSData *)saltData iterations:(NSUInteger)iterations;
- (NSData *)pbkdf2hashPasswordWithSalt:(NSData *)saltData iterations:(NSUInteger)iterations	keyLength:(NSUInteger)keylength;

@end


@interface NSData (PBKDF2)

+ (NSNumber *)pbkdf2IterationsOnCurrentHardware;

- (NSData *)pbkdf2hashWithSalt:(NSData *)saltData;
- (NSData *)pbkdf2hashWithSalt:(NSData *)saltData iterations:(NSUInteger)iterations;
- (NSData *)pbkdf2hashWithSalt:(NSData *)saltData iterations:(NSUInteger)iterations	keyLength:(NSUInteger)keylength;

@end

