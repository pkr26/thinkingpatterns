import UIKit
internal import Expo

/// Connect the existing React Native application window to its single scene.
final class SceneDelegate: ExpoAppSceneDelegate {

  override func scene(
    _ scene: UIScene,
    willConnectTo session: UISceneSession,
    options connectionOptions: UIScene.ConnectionOptions
  ) {
    guard let windowScene = scene as? UIWindowScene else { return }
    guard let appDelegate = UIApplication.shared.delegate as? AppDelegate,
          let applicationWindow = appDelegate.window else {
      preconditionFailure("The application must initialize its React Native window before connecting a scene.")
    }

    window = applicationWindow
    applicationWindow.windowScene = windowScene
    applicationWindow.frame = windowScene.coordinateSpace.bounds
    applicationWindow.makeKeyAndVisible()
  }
}
