#import <XCTest/XCTest.h>
#import <HealthKit/HealthKit.h>
#import <React/RCTBridgeModule.h>
#import <objc/runtime.h>
#import "RCTAppleHealthKit.h"

// These declarations expose the real compiled category; no implementation copy.
@interface RCTAppleHealthKit (NativeMutationTestDeclarations)
- (void)requestAuthorization:(NSDictionary *)scopes
                            :(RCTPromiseResolveBlock)resolve
                            :(RCTPromiseRejectBlock)reject;
- (void)saveStateOfMind:(NSDictionary *)sample
                       :(RCTPromiseResolveBlock)resolve
                       :(RCTPromiseRejectBlock)reject;
@end

static NSUInteger requestCount;
static NSSet *observedShareTypes;
static NSSet *observedReadTypes;

// Native message-boundary spy: do not display authorization UI or grant access.
static void ObserveRequest(id store, SEL selector, NSSet *share, NSSet *read,
                           void (^completion)(BOOL, NSError *)) {
  (void)store; (void)selector; (void)completion;
  requestCount += 1;
  observedShareTypes = [share copy];
  observedReadTypes = [read copy];
}

// The invalid-argument mutant must never write health data during a test.
static HKAuthorizationStatus DenyWrites(id store, SEL selector, HKObjectType *type) {
  (void)store; (void)selector; (void)type;
  return HKAuthorizationStatusSharingDenied;
}

@interface NativeHealthBridgeTests : XCTestCase
@end

@implementation NativeHealthBridgeTests

- (void)testNativeAuthorizationPassesOnlyShareTypeAndNoReadTypes {
  if (@available(iOS 18.0, *)) {
    if (![HKHealthStore isHealthDataAvailable]) {
      XCTSkip(@"Actual HealthKit availability is required; it is not overridden.");
      return;
    }
    SEL selector = @selector(requestAuthorizationToShareTypes:readTypes:completion:);
    Method method = class_getInstanceMethod([HKHealthStore class], selector);
    XCTAssertNotEqual(method, NULL);
    if (method == NULL) return;
    requestCount = 0; observedShareTypes = nil; observedReadTypes = nil;
    IMP original = method_setImplementation(method, (IMP)ObserveRequest);
    @try {
      RCTAppleHealthKit *bridge = [RCTAppleHealthKit new];
      [bridge requestAuthorization:@{}
                                  :^(__unused id value) { XCTFail(@"Spy does not complete authorization."); }
                                  :^(__unused NSString *code, __unused NSString *message,
                                     __unused NSError *error) { XCTFail(@"Request must reach native boundary."); }];
      XCTAssertEqual(requestCount, 1u);
      XCTAssertEqualObjects(observedShareTypes, [NSSet setWithObject:[HKObjectType stateOfMindType]]);
      XCTAssertNil(observedReadTypes, @"Write-only bridge must pass nil read types.");
    } @finally {
      method_setImplementation(method, original);
      observedShareTypes = nil; observedReadTypes = nil; requestCount = 0;
    }
  } else {
    XCTSkip(@"Requires a real iOS18-or-later native runtime.");
  }
}

- (void)testNativeValenceRejectsBothFiniteOutOfRangeValuesBeforeHealthAccess {
  // Denial is a declared native boundary seam, solely preventing any mutated
  // path from saving data. UIKit/HealthKit classes and bridge remain real.
  Method method = class_getInstanceMethod([HKHealthStore class],
                                         @selector(authorizationStatusForType:));
  XCTAssertNotEqual(method, NULL);
  if (method == NULL) return;
  IMP original = method_setImplementation(method, (IMP)DenyWrites);
  @try {
    for (NSNumber *valence in @[@(-2.0), @(2.0)]) {
      __block NSString *rejectionCode = nil;
      __block NSUInteger rejected = 0, resolved = 0;
      RCTAppleHealthKit *bridge = [RCTAppleHealthKit new];
      [bridge saveStateOfMind:@{ @"kind": @"neutral", @"valence": valence, @"date": @"2026-10-19" }
                             :^(__unused id value) { resolved += 1; }
                             :^(NSString *code, __unused NSString *message, __unused NSError *error) {
                               rejected += 1; rejectionCode = [code copy];
                             }];
      XCTAssertEqual(rejected, 1u);
      XCTAssertEqual(resolved, 0u);
      XCTAssertEqualObjects(rejectionCode, @"E_ARGUMENT");
    }
  } @finally {
    method_setImplementation(method, original);
  }
}
@end
