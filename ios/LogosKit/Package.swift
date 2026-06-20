// swift-tools-version:5.9
import PackageDescription

// LogosKit wraps the Rust core (logos-ffi) for Swift. Both the binary
// `LogosFFI.xcframework` and the generated `Sources/LogosKit/Generated/logos_ffi.swift`
// are produced by `scripts/build-ios.sh` and are gitignored build artifacts —
// run that script (on macOS) before building an app against this package.
let package = Package(
    name: "LogosKit",
    platforms: [.iOS(.v16), .macOS(.v12)],
    products: [
        .library(name: "LogosKit", targets: ["LogosKit"])
    ],
    targets: [
        .binaryTarget(name: "LogosFFI", path: "LogosFFI.xcframework"),
        .target(
            name: "LogosKit",
            dependencies: ["LogosFFI"],
            path: "Sources/LogosKit"
        ),
    ]
)
