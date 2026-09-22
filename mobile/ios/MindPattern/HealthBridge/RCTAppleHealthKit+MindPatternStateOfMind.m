/**
 * MindPattern State-of-Mind bridge (2026-09-22, independent-audit NEW-2 /
 * 2026-09-21 audit E-1's HealthKit half).
 *
 * react-native-health@1.19.0 (the newest published version) links and
 * autolinks, but its native module predates iOS 18: it exposes
 * initHealthKit/isAvailable/getAuthStatus and NO State of Mind path, so
 * src/healthkit.ts's seam (which requires requestAuthorization and
 * saveStateOfMind) always read the package as "too old" and the mirror
 * stayed permanently unavailable. This category adds exactly the three
 * methods the seam's documented contract names
 * (mobile/src/healthkit.ts, "NATIVE-MODULE CONTRACT"), promise-based,
 * onto the module the JS wrapper already spreads:
 *
 *   HealthKit = Object.assign({}, NativeModules.AppleHealthKit, {...})
 *
 * so no JS-side probing change is needed — the methods appear on the
 * module the moment this file compiles into the app target.
 *
 * API facts pinned against Apple's doc JSON (developer.apple.com
 * /tutorials/data/documentation/healthkit/hkstateofmind.json):
 *   - HKStateOfMind is an ObjC class (HKSample subclass), built with the
 *     class factory +stateOfMindWithDate:kind:valence:labels:associations:
 *   - kind is HKStateOfMindKind (HKStateOfMindKindMomentaryEmotion /
 *     HKStateOfMindKindDailyMood); MindPattern mirrors the daily mood
 *     check-in, so every write is a DailyMood with a discrete valence.
 *   - The share type is [HKObjectType stateOfMindType] (HKStateOfMindType).
 *   - Saving goes through the EXISTING -saveObject:withCompletion: (the
 *     WWDC24 session's "use the existing save method").
 *
 * PRIVACY POSTURE (matches the JS seam, write-only): authorization is
 * requested for SHARE only; nothing is ever read back from HealthKit.
 *
 * Availability: the app's deployment target is iOS 15.1 and State of Mind
 * ships in iOS 18. Every entry point is @available-gated; on older
 * systems the methods answer honestly (resolve false / reject) so the
 * JS seam surfaces "unavailable", never a crash. Classes referenced only
 * inside @available blocks are weak-imported automatically by the modern
 * toolchain, so the binary still launches on iOS 15/16/17.
 */
#import <Foundation/Foundation.h>
#import <HealthKit/HealthKit.h>
#import <React/RCTBridgeModule.h>

// The class lives in the react-native-health pod; a forward declaration
// is all the app target needs to attach a category to it (the pod's own
// headers are not on the app target's search path, and do not need to be).
@class RCTAppleHealthKit;

@interface RCTAppleHealthKit (MindPatternStateOfMind)
@end

static NSString *const kBridgeErrorDomain = @"MindPatternHealthBridge";

// The five valence classifications the JS seam may send (the label is
// advisory context from the check-in; HealthKit's own valence integer is
// the authoritative value and is what gets written).
static NSSet<NSString *> *ValidKindLabels(void) {
  static NSSet<NSString *> *labels;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    labels = [NSSet setWithArray:@[
      @"very_unpleasant", @"unpleasant", @"neutral", @"pleasant", @"very_pleasant"
    ]];
  });
  return labels;
}

// The share type every method here touches: the State of Mind category,
// WRITE-only by construction (it is never passed as a read type).
static HKStateOfMindType *StateOfMindShareType(void) {
  if (@available(iOS 18.0, *)) {
    return [HKObjectType stateOfMindType];
  }
  return nil;
}

@implementation RCTAppleHealthKit (MindPatternStateOfMind)

/**
 * Ask (or re-ask) for WRITE access to the State of Mind category.
 * HealthKit quirk this implements for the seam: the request call itself
 * resolves even when the user denies, so the authorization status is
 * consulted afterwards — only an explicit sharingDenied answers false.
 * `scopes` is accepted (and ignored) for signature parity with the
 * community package's other methods; the scope is fixed to the single
 * State-of-Mind write category by design, so a caller cannot widen it.
 */
RCT_EXPORT_METHOD(requestAuthorization
                  : (NSDictionary *)scopes
                  : (RCTPromiseResolveBlock)resolve
                  : (RCTPromiseRejectBlock)reject)
{
  (void)scopes;
  if (@available(iOS 18.0, *)) {
    if (![HKHealthStore isHealthDataAvailable]) {
      resolve(@(NO));
      return;
    }
    HKHealthStore *store = [[HKHealthStore alloc] init];
    HKStateOfMindType *type = StateOfMindShareType();
    [store requestAuthorizationToShareTypes:[NSSet setWithObject:type]
                                  readTypes:nil
                                 completion:^(__unused BOOL granted, NSError *_Nullable error) {
                                   if (error != nil) {
                                     reject(@"E_AUTHORIZATION",
                                            error.localizedDescription ?: @"authorization failed",
                                            error);
                                     return;
                                   }
                                   // The request resolves on denial too —
                                   // only the post-hoc status is truth.
                                   HKAuthorizationStatus status = [store authorizationStatusForType:type];
                                   resolve(@(status != HKAuthorizationStatusSharingDenied));
                                 }];
    return;
  }
  // Pre-iOS-18: State of Mind does not exist; report unavailable, not broken.
  resolve(@(NO));
}

/**
 * Report the current authorization status for the State of Mind category,
 * shaped { stateOfMind: <HKAuthorizationStatus> } (0 notDetermined,
 * 1 sharingDenied, 2 sharingAuthorized) exactly as the JS seam reads it.
 */
RCT_EXPORT_METHOD(getAuthorizationStatus
                  : (NSDictionary *)scopes
                  : (RCTPromiseResolveBlock)resolve
                  : (RCTPromiseRejectBlock)reject)
{
  (void)scopes;
  if (@available(iOS 18.0, *)) {
    if (![HKHealthStore isHealthDataAvailable]) {
      reject(@"E_UNAVAILABLE", @"HealthKit data is not available on this device", nil);
      return;
    }
    HKHealthStore *store = [[HKHealthStore alloc] init];
    HKAuthorizationStatus status = [store authorizationStatusForType:StateOfMindShareType()];
    resolve(@{ @"stateOfMind": @(status) });
    return;
  }
  resolve(@{ @"stateOfMind": @(0) }); // notDetermined on systems without the type
}

/**
 * Persist ONE mood check-in as an HKStateOfMind daily-mood sample:
 * { kind, valence, date } where valence is HealthKit's discrete -2..2
 * classification and date is an ISO-8601 local calendar day ("yyyy-MM-dd",
 * interpreted in the device's local calendar). Out-of-range valences and
 * unknown kind labels are rejected — a hostile caller must not be able to
 * write arbitrary HealthKit payloads through this bridge.
 */
RCT_EXPORT_METHOD(saveStateOfMind
                  : (NSDictionary *)sample
                  : (RCTPromiseResolveBlock)resolve
                  : (RCTPromiseRejectBlock)reject)
{
  if (![sample isKindOfClass:[NSDictionary class]]) {
    reject(@"E_ARGUMENT", @"saveStateOfMind expects a sample object", nil);
    return;
  }
  NSString *kind = sample[@"kind"];
  if (![kind isKindOfClass:[NSString class]] || ![ValidKindLabels() containsObject:kind]) {
    reject(@"E_ARGUMENT", @"saveStateOfMind: unknown kind label", nil);
    return;
  }
  NSNumber *valenceNumber = sample[@"valence"];
  if (![valenceNumber isKindOfClass:[NSNumber class]]) {
    reject(@"E_ARGUMENT", @"saveStateOfMind: valence must be a number", nil);
    return;
  }
  const double valence = valenceNumber.doubleValue;
  if (valence < -2.0 || valence > 2.0) {
    reject(@"E_ARGUMENT", @"saveStateOfMind: valence must be within [-2, 2]", nil);
    return;
  }
  NSString *dateISO = sample[@"date"];
  if (![dateISO isKindOfClass:[NSString class]]) {
    reject(@"E_ARGUMENT", @"saveStateOfMind: date must be an ISO calendar day", nil);
    return;
  }
  NSDateFormatter *formatter = [[NSDateFormatter alloc] init];
  formatter.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
  formatter.dateFormat = @"yyyy-MM-dd";
  // No timeZone set: the seam's contract is the LOCAL calendar day, which
  // is what a nil (device-default) zone parses.
  NSDate *date = [formatter dateFromString:dateISO];
  if (date == nil) {
    reject(@"E_ARGUMENT", @"saveStateOfMind: date must be yyyy-MM-dd", nil);
    return;
  }

  if (@available(iOS 18.0, *)) {
    if (![HKHealthStore isHealthDataAvailable]) {
      reject(@"E_UNAVAILABLE", @"HealthKit data is not available on this device", nil);
      return;
    }
    HKHealthStore *store = [[HKHealthStore alloc] init];
    HKStateOfMindType *type = StateOfMindShareType();
    // Mirror the seam's write path: consult the status before writing so
    // a denial answers false here instead of failing inside the save.
    HKAuthorizationStatus status = [store authorizationStatusForType:type];
    if (status == HKAuthorizationStatusSharingDenied) {
      resolve(@(NO));
      return;
    }
    HKStateOfMind *stateOfMind = [HKStateOfMind stateOfMindWithDate:date
                                                                kind:HKStateOfMindKindDailyMood
                                                             valence:valence
                                                              labels:nil
                                                        associations:nil];
    [store saveObject:stateOfMind
        withCompletion:^(__unused BOOL success, NSError *_Nullable error) {
          if (error != nil) {
            reject(@"E_SAVE", error.localizedDescription ?: @"saving the state of mind failed", error);
            return;
          }
          resolve(@(YES));
        }];
    return;
  }
  reject(@"E_UNAVAILABLE", @"State of Mind requires iOS 18 or later", nil);
}

@end
