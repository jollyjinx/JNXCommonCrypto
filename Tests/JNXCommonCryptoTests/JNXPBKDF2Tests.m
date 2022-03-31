//
//  JNXPBKDF2Tests.m
//  JNXCommonCrypto
//
//  Created by Patrick Stein on 4/30/13.
//  Copyright (c) 2013 Patrick Stein. All rights reserved.
//

#import "JNXPBKDF2Tests.h"
#import "JNXCommonCrypto.h"

@implementation JNXPBKDF2Tests

- (void)testAIterationsForHardware
{
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);
	NSLog(@"%@",[NSData pbkdf2IterationsOnCurrentHardware]);

	for( int i=0; i<10; i++)
	{
		XCTAssertFalse( [[NSData pbkdf2IterationsOnCurrentHardware] integerValue]<1000 ,@"Not enough iterations");
	}
}

- (void)testBHashesAgainstDefaults
{
	{
		uint8_t	salt1234[]	= { 0x01, 0x02, 0x03, 0x04 ,0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,0x12, 0x13, 0x14 };
		NSData	*saltData	= [NSData dataWithBytes:salt1234 length:sizeof(salt1234)];

		NSData	*calculatedData	= [[@"password" dataUsingEncoding:NSUTF8StringEncoding] pbkdf2hashWithSalt:saltData];
		NSData	*expectedData 	= [@"63a95193d1df7276338638c1b878968f491b7defddeff154" hexstringData];

		XCTAssertTrue( [expectedData isEqual:calculatedData], @"Expected %@ got %@",expectedData,calculatedData);
	}
	{
		NSData	*saltData		= [@"salt" dataUsingEncoding:NSUTF8StringEncoding];
		NSData	*calculatedData	= [[@"password" dataUsingEncoding:NSUTF8StringEncoding] pbkdf2hashWithSalt:saltData iterations:4096];
		NSData	*expectedData 	= [@"4b007901b765489abead49d926f721d065a429c12e463f6c" hexstringData];

		XCTAssertTrue( [expectedData isEqual:calculatedData], @"Expected %@ got %@",expectedData,calculatedData);
	}
}

- (void)testCEdgeCases
{
	XCTAssertTrue( 24==[[[NSData data] pbkdf2hashWithSalt:[NSData randomSalt] iterations:1000] length] ,@"Not enough iterations");
	{
		NSData	*saltData		= [@"salt" dataUsingEncoding:NSUTF8StringEncoding];
		NSData	*calculatedData	= [[NSData data] pbkdf2hashWithSalt:saltData iterations:4096];
		NSData	*expectedData 	= [@"a5d20db4d34063c4f1674ad73e7dc664828e9ae91e03597a" hexstringData];


		XCTAssertTrue( [expectedData isEqual:calculatedData], @"Expected %@ got %@",expectedData,calculatedData);
	}

	for( int i=0; i<100; i++)
	{
		NSLog(@"%d",i);
		XCTAssertTrue( 24==[[[NSData randomDataWithLength:i] pbkdf2hashWithSalt:[NSData randomSalt] iterations:1000] length] ,@"Not enough iterations");
	}
}


@end
