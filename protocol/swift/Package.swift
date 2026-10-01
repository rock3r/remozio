// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioProtocol",
    platforms: [.macOS(.v26)],
    products: [.library(name: "RemozioProtocol", targets: ["RemozioProtocol"])],
    targets: [
        .target(name: "RemozioProtocol"),
        .testTarget(name: "RemozioProtocolTests", dependencies: ["RemozioProtocol"]),
    ]
)
