import UIKit
import XCTest
@testable import MindPattern

/// Observe the actual hosted application; no replacement window or delegate.
final class NativeSceneCompatibilityTests: XCTestCase {
  @MainActor
  func testActualApplicationWindowIsConnectedVisibleAndOwnsReactRoot() throws {
    let application = UIApplication.shared
    let appDelegate = try XCTUnwrap(application.delegate as? AppDelegate)
    let window = try XCTUnwrap(appDelegate.window)
    let scene = try XCTUnwrap(window.windowScene)
    let sceneDelegate = try XCTUnwrap(scene.delegate as? SceneDelegate)
    let root = try XCTUnwrap(window.rootViewController)

    XCTAssertTrue(sceneDelegate.window === window)
    XCTAssertTrue(application.connectedScenes.contains(scene))
    XCTAssertEqual(scene.session.role, .windowApplication)
    XCTAssertEqual(scene.activationState, .foregroundActive)
    XCTAssertTrue(scene.windows.contains { $0 === window })
    XCTAssertFalse(window.isHidden)
    XCTAssertEqual(window.alpha, 1)
    let windows = scene.windows.map { "\(type(of: $0)) key=\($0.isKeyWindow) hidden=\($0.isHidden) level=\($0.windowLevel.rawValue) root=\(String(describing: $0.rootViewController))" }
    XCTAssertTrue(window.isKeyWindow, "Actual scene windows: \(windows)")
    XCTAssertEqual(window.frame, scene.coordinateSpace.bounds)
    XCTAssertFalse(window.bounds.isEmpty)
    XCTAssertTrue(root.viewIfLoaded?.window === window)
    XCTAssertNotNil(appDelegate.reactNativeFactory)
    XCTAssertNotNil(appDelegate.reactNativeDelegate)
  }
}
