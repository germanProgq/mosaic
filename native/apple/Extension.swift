import Foundation
import NetworkExtension

@main
struct ExtensionMain {
    static func main() {
        autoreleasepool { NEProvider.startSystemExtensionMode() }
        dispatchMain()
    }
}
