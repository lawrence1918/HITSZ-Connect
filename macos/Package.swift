// swift-tools-version: 5.10
import PackageDescription

// The application bundle itself is assembled by scripts/build-app.sh.  Keeping
// this as a dependency-free SwiftPM executable makes local development work on
// any macOS host with the Command Line Tools installed.
let package = Package(
    name: "HITSZConnect",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "HITSZConnect", targets: ["HITSZConnectApp"])
    ],
    targets: [
        .executableTarget(
            name: "HITSZConnectApp",
            path: "Sources/HITSZConnectApp"
        ),
        .testTarget(
            name: "HITSZConnectAppTests",
            dependencies: ["HITSZConnectApp"],
            path: "Tests/HITSZConnectAppTests"
        )
    ],
    swiftLanguageVersions: [.v5]
)
