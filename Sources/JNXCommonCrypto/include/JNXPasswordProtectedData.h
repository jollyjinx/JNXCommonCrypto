//
//  JNXPasswordProtectedData.h
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 5/22/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

@import Foundation;

@interface JNXPasswordProtectedData : NSObject <NSCoding,NSCopying>

@property (nonatomic,readonly)		NSData		*encryptedData;
@property (nonatomic,readonly)		NSData 		*iv;
@property (nonatomic,readonly)		NSData		*salt;
@property (nonatomic,readonly)		NSNumber	*iterations;

+ newWithData:(NSData *)plainData password:(NSData *)passwordData;
- initWithData:(NSData *)plainData password:(NSData *)passwordData;

+ newWithData:(NSData *)plainData passphrase:(NSString *)passphrase;
- initWithData:(NSData *)plainData passphrase:(NSString *)passphrase;

+ newWithEncryptedData:(NSData *)encryptedData iv:(NSData *)iv salt:(NSData *)salt iterations:(NSNumber *)iterations;
- initWithEncryptedData:(NSData *)encryptedData iv:(NSData *)iv salt:(NSData *)salt iterations:(NSNumber *)iterations;

- (NSData *)decryptedDataWithPassword:(NSData *)passwordData;
- (NSData *)decryptedDataWithPassphrase:(NSString *)passphrase;


@end
