// App-host XCTest regression for native HealthKit event delivery compatibility.
#import <XCTest/XCTest.h>
#import <React/RCTBridgeModule.h>
#import <RNAppleHealthKit/RCTAppleHealthKit.h>

@interface RCTAppleHealthKit (NativeEventCompatibilityInspection)
- (void)emitEventInternal:(NSNotification *)notification;
@end

@interface NativeHealthEventCompatibilityTests : XCTestCase
@end

@implementation NativeHealthEventCompatibilityTests

- (void)testUsesInjectedBridgelessCallableModuleAndPreservesListenerGate
{
  // This is the real compiled package singleton and its real event method.
  // The sole seam records the RN-to-JavaScript invocation boundary.
  RCTAppleHealthKit *module = [RCTAppleHealthKit new];
  RCTCallableJSModules *previous = module.callableJSModules;
  BOOL previousHasListeners = module.hasListeners;
  RCTCallableJSModules *injected = [RCTCallableJSModules new];
  NSMutableArray<NSDictionary *> *events = [NSMutableArray new];
  [injected setBridgelessJSModuleMethodInvoker:^(NSString *name, NSString *method,
                                                NSArray *arguments, dispatch_block_t completion) {
    [events addObject:@{ @"module": name, @"method": method, @"args": arguments }];
    if (completion) {
      completion();
    }
  }];
  NSString *eventName = @"change:steps";
  NSDictionary *payload = @{ @"steps": @7 };
  BOOL added = NO;
  @try {
    module.callableJSModules = injected;
    [module addListener:eventName];
    added = YES;
    module.hasListeners = YES;
    [module emitEventInternal:[NSNotification notificationWithName:eventName object:nil userInfo:payload]];
    XCTAssertEqual(module.callableJSModules, injected);
    XCTAssertEqualObjects(events, (@[ @{ @"module": @"RCTDeviceEventEmitter", @"method": @"emit",
                                       @"args": @[ eventName, payload ] } ]));

    module.hasListeners = NO;
    [module emitEventInternal:[NSNotification notificationWithName:eventName object:nil userInfo:payload]];
    XCTAssertEqual(events.count, 1U);
    XCTAssertEqual(module.callableJSModules, injected);

    module.hasListeners = YES;
    [module emitEventInternal:[NSNotification notificationWithName:eventName object:nil userInfo:nil]];
    XCTAssertEqual(events.count, 2U);
    XCTAssertEqualObjects(events.lastObject[@"args"], (@[ eventName ]));
    XCTAssertEqual(module.callableJSModules, injected);
  } @finally {
    if (added) {
      [module removeListeners:1];
    }
    module.hasListeners = previousHasListeners;
    module.callableJSModules = previous;
  }
}

@end
