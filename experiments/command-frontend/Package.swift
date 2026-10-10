// swift-tools-version: 6.2
import PackageDescription

let package = Package(name: "CommandFrontendExperiment", platforms: [.macOS("26.0")],
    dependencies: [.package(path: "../../macos/core"), .package(path: "../../protocol/swift")],
    targets: [.target(name: "OwnedTTY"), .executableTarget(name: "CommandFrontendFixture", dependencies: [
        "OwnedTTY",
        .product(name: "RemozioCore", package: "core"), .product(name: "RemozioProtocol", package: "swift")])])
