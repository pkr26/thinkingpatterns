import UIKit
import XCTest
@testable import MindPattern

/// Hosted tests of the production delegate. No replacement delegate or getter.
final class NativePrivacyTests: XCTestCase {
  @MainActor
  private func actualWindow() throws -> UIWindow {
    guard !UIScreen.main.isCaptured else {
      throw XCTSkip("Requires an actually uncaptured native screen; no getter is overridden.")
    }
    let delegate = try XCTUnwrap(UIApplication.shared.delegate as? AppDelegate)
    return try XCTUnwrap(delegate.window)
  }

  @MainActor
  private func privacyCovers(_ window: UIWindow) -> [UIView] {
    window.subviews.filter { $0.accessibilityLabel == "Fathom privacy screen" }
  }

  @MainActor
  func testSnapshotCoverIsPresentAtWillResignBeforeAnyBackgroundEvent() throws {
    let window = try actualWindow()
    NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification,
                                    object: UIApplication.shared)
    defer {
      NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification,
                                      object: UIApplication.shared)
    }
    XCTAssertTrue(privacyCovers(window).isEmpty)
    NotificationCenter.default.post(name: UIApplication.willResignActiveNotification,
                                    object: UIApplication.shared)
    // Deliberately do not post didEnterBackground. Observe UIKit synchronously.
    let covers = privacyCovers(window)
    XCTAssertEqual(covers.count, 1, "Native snapshot shield must already exist at resignation.")
    let cover = try XCTUnwrap(covers.first)
    XCTAssertEqual(cover.frame, window.bounds)
    XCTAssertEqual(cover.alpha, 1)
    XCTAssertEqual(cover.backgroundColor?.cgColor.alpha, 1)
    XCTAssertTrue(cover.accessibilityViewIsModal)
  }

  @MainActor
  func testActualUncapturedScreenDoesNotCreateCaptureCover() throws {
    let window = try actualWindow()
    NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification,
                                    object: UIApplication.shared)
    defer {
      NotificationCenter.default.post(name: UIApplication.didBecomeActiveNotification,
                                      object: UIApplication.shared)
    }
    XCTAssertFalse(UIScreen.main.isCaptured)
    NotificationCenter.default.post(name: UIScreen.capturedDidChangeNotification,
                                    object: UIScreen.main)
    XCTAssertFalse(UIScreen.main.isCaptured, "External capture must not change during this case.")
    XCTAssertTrue(privacyCovers(window).isEmpty,
                  "An actual uncaptured screen must not be hidden by the capture branch.")
  }
}
