import UIKit
import React
import React_RCTAppDelegate
import ReactAppDependencyProvider

@main
class AppDelegate: UIResponder, UIApplicationDelegate {
  var window: UIWindow?

  var reactNativeDelegate: ReactNativeDelegate?
  var reactNativeFactory: RCTReactNativeFactory?

  /// Cover the window synchronously before iOS takes an app-switcher
  /// snapshot. The JavaScript overlay cannot guarantee that timing.
  private var snapshotShield: UIView?

  /// Hide journal content while the screen is being recorded or mirrored.
  /// Keep this cover independent from the app-transition cover.
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
    // Track recording and mirroring while the app is in the foreground.
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

  // Independent lifecycles prevent one transition from removing the
  // other privacy cover while recording or mirroring is still active.
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
