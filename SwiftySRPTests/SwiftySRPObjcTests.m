//
//  SwiftySRPObjcTests.m
//  SwiftySRP
//
//  Created by Sergey A. Novitsky on 20/02/2017.
//  Copyright © 2017 Flock of Files. All rights reserved.
//

#import <Foundation/Foundation.h>
@import XCTest;
@import SwiftySRP;

@interface SwiftySRPObjcTests : XCTestCase

@end

@implementation SwiftySRPObjcTests

- (void)setUp
{
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
}
    
- (void)tearDown
{
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

- (void)testObjcAPI
{
    NSData* N = [[NSData alloc] init];
    NSData* g = [[NSData alloc] init];
    NSError* error = nil;
    
    [SRPObjC configurationWithN:N g:g digest:^NSData * _Nonnull(NSData * _Nonnull aData) {
        return aData;
    } hmac:^NSData * _Nonnull(NSData * _Nonnull aKey, NSData * _Nonnull aData) {
        return aData;
    } error:&error];
    
}

@end
