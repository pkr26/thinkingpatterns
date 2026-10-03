import UIKit
import React
import React_RCTAppDelegate
import ReactAppDependencyProvider

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?

  var reactNativeDelegate: ReactNativeDelegate?
  var reactNativeFactory: RCTReactNativeFactory?

  /// Opaque cover placed over the window the moment the app resigns
  /// active (audit F-3, 2026-09-26). The JS shield in App.tsx renders
  /// asynchronously through the bridge and can lose the race against the
  /// app-switcher snapshot; these notification observers run
  /// synchronously on the main thread BEFORE iOS captures the
  /// transition snapshot, so decrypted journal content can never appear
  /// in the switcher thumbnail. The JS overlay stays as belt-and-braces
  /// and for the themed color.
  private var snapshotShield: UIView?

  /// S-7 (pentest 2026-09-26): iOS has no FLAG_SECURE — while the app is
  /// FOREGROUND-ACTIVE, a QuickTime/AirPlay/screen-recording capture
  /// sees decrypted journal text live. UIScreen.isCaptured is the one
  /// signal the platform offers; when it turns on, the same opaque cover
  /// goes up until recording stops. A deliberate cover beats hoping the
  /// user notices the red status-bar pill.
  private var captureShield: UIView?

  func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
  ) -> Bool {
    let delegate = ReactNativeDelegate()
    let factory = RCTReactNativeFactory(delegate: delegate)
    delegate.dependencyProvider = RCTAppDependencyProvider()

    reactNativeDelegate = delegate
    reactNativeFactory = factory

    window = UIWindow(frame: UIScreen.main.bounds)

    factory.startReactNative(
      withModuleName: "MindPattern",
      in: window,
      launchOptions: launchOptions
    )

    NotificationCenter.default.addObserver(
      self,
      selector: #selector(showSnapshotShield),
      name: UIApplication.willResignActiveNotification,
      object: nil
    )
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(hideSnapshotShield),
      name: UIApplication.didBecomeActiveNotification,
      object: nil
    )
    // S-7: screen recording / mirroring of the foreground app.
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(captureStateChanged),
      name: UIScreen.capturedDidChangeNotification,
      object: nil
    )

    captureStateChanged()
    return true
  }

  deinit {
    NotificationCenter.default.removeObserver(self)
  }

  @objc private func showSnapshotShield() {
    guard let window = window, snapshotShield == nil else { return }
    let shield = UIView(frame: window.bounds)
    // Matches the app's dark ink color so the cover reads as the app's
    // own chrome, and stays opaque regardless of light/dark theme (a
    // solid cover must never hint at content underneath).
    shield.backgroundColor = UIColor(red: 0.11, green: 0.14, blue: 0.19, alpha: 1.0)
    shield.autoresizingMask = [.flexibleWidth, .flexibleHeight]
    shield.isAccessibilityElement = true
    shield.accessibilityLabel = "Fathom privacy screen"
    shield.accessibilityViewIsModal = true
    window.addSubview(shield)
    snapshotShield = shield
  }

  @objc private func hideSnapshotShield() {
    snapshotShield?.removeFromSuperview()
    snapshotShield = nil
    captureStateChanged()
  }

  // S-7: the recording cover is INDEPENDENT of the transition shield so
  // the two lifecycles (capture on/off, active/resigned) can overlap
  // freely without one removing the other's cover.
  @objc private func captureStateChanged() {
    if UIScreen.main.isCaptured {
      guard let window = window, captureShield == nil else { return }
      let shield = UIView(frame: window.bounds)
      shield.backgroundColor = UIColor(red: 0.11, green: 0.14, blue: 0.19, alpha: 1.0)
      shield.autoresizingMask = [.flexibleWidth, .flexibleHeight]
      shield.isAccessibilityElement = true
    shield.accessibilityLabel = "Fathom privacy screen"
    shield.accessibilityViewIsModal = true
      window.addSubview(shield)
      captureShield = shield
    } else {
      captureShield?.removeFromSuperview()
      captureShield = nil
    }
  }
}

class ReactNativeDelegate: RCTDefaultReactNativeFactoryDelegate {
  override func sourceURL(for bridge: RCTBridge) -> URL? {
    self.bundleURL()
  }

  override func bundleURL() -> URL? {
#if DEBUG
    RCTBundleURLProvider.sharedSettings().jsBundleURL(forBundleRoot: "index")
#else
    Bundle.main.url(forResource: "main", withExtension: "jsbundle")
#endif
  }
}
