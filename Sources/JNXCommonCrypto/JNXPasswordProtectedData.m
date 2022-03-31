//
//  JNXPasswordProtectedData.m
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 5/22/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

#import "JNXPasswordProtectedData.h"
#import "JNXCommonCrypto.h"
#import "JNXLog.h"

static NSString *kS_encryptedSalt		= @"s";
static NSString *kS_encryptedIV			= @"i";
static NSString *kS_encryptedIterations	= @"t";
static NSString *kS_encryptedData		= @"e";


@implementation JNXPasswordProtectedData
{
	NSData	*_plainDataCache;
	NSData	*_passwordSHA1Data;
}


- (id)copyWithZone:(NSZone *)zone
{
	return [[[self class] alloc] initWithEncryptedData:(NSData *)_encryptedData iv:(NSData *)_iv salt:(NSData *)_salt iterations:(NSNumber *)_iterations];
}

- (void)encodeWithCoder:(NSCoder *)encoder
{
    [encoder encodeObject:_salt				forKey:kS_encryptedSalt];
    [encoder encodeObject:_iv				forKey:kS_encryptedIV];
    [encoder encodeObject:_iterations		forKey:kS_encryptedIterations];
    [encoder encodeObject:_encryptedData	forKey:kS_encryptedData];
}

- (id)initWithCoder:(NSCoder *)decoder
{
	if( !(self = [super init]) )
	{
		return nil;
	}
	_salt			=	[decoder decodeObjectForKey:kS_encryptedSalt];
	_iv				=	[decoder decodeObjectForKey:kS_encryptedIV];
	_iterations		=	[decoder decodeObjectForKey:kS_encryptedIterations];
	_encryptedData	= 	[decoder decodeObjectForKey:kS_encryptedData];

	return self;
}


+ newWithData:(NSData *)plainData password:(NSData *)passwordData
{
	return [[self alloc] initWithData:plainData password:passwordData];
}

- initWithData:(NSData *)plainData password:(NSData *)passwordData
{
	if( !(self = [super init]) )
	{
		return nil;
	}
	_salt				=	[NSData randomSalt];
	_iv					=	[NSData randomIV];
	_iterations			=	[NSData pbkdf2IterationsOnCurrentHardware];
	_encryptedData		= 	[plainData encryptDataWithPassword:passwordData salt:_salt pbkdf2Iterations:_iterations initialisationVector:_iv];

	_plainDataCache		=	[passwordData copy];
	_passwordSHA1Data	=	[passwordData sha1DataCompatible];

	return self;
}

+ newWithData:(NSData *)plainData passphrase:(NSString *)passphrase
{
	return [[self alloc] initWithData:plainData password:[passphrase dataUsingEncoding:NSUTF8StringEncoding]];
}
- initWithData:(NSData *)plainData passphrase:(NSString *)passphrase
{
	return [self initWithData:plainData password:[passphrase dataUsingEncoding:NSUTF8StringEncoding]];
}

+ newWithEncryptedData:(NSData *)encryptedData iv:(NSData *)iv salt:(NSData *)salt iterations:(NSNumber *)iterations;
{
	return [[self alloc] initWithEncryptedData:encryptedData iv:iv salt:salt iterations:iterations];
}

- initWithEncryptedData:(NSData *)encryptedData iv:(NSData *)iv salt:(NSData *)salt iterations:(NSNumber *)iterations;
{
	if( !(self = [super init]) )
	{
		return nil;
	}
	_salt			=	salt;
	_iv				=	iv;
	_iterations		=	iterations;
	_encryptedData	= 	encryptedData;

	return self;
}

- (NSData *)decryptedDataWithPassword:(NSData *)passwordData
{
	if( _passwordSHA1Data && [_passwordSHA1Data isEqualToData:[passwordData sha1DataCompatible]] )
	{
		return _plainDataCache;
	}

	if( (_plainDataCache = [_encryptedData decryptDataWithPassword:passwordData salt:_salt pbkdf2Iterations:_iterations initialisationVector:_iv]) )
	{
		_passwordSHA1Data		=	[passwordData sha1DataCompatible];
	}

	return [_plainDataCache copy];
}

- (NSData *)decryptedDataWithPassphrase:(NSString *)passphrase
{
	return [self decryptedDataWithPassword:[passphrase dataUsingEncoding:NSUTF8StringEncoding]];
}

- (NSString *)description
{
	return [NSString stringWithFormat:@"%@(salt:%@ iv:%@ iterations:%@ encryptedData:%@ cached:%@)",NSStringFromClass([self class]),_salt,_iv,_iterations,_encryptedData,_passwordSHA1Data?@"YES":@"NO"];
}


@end
