// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioCore",
    platforms: [.macOS("26.0")],
    products: [.library(name: "RemozioCore", targets: ["RemozioCore"])],
    dependencies: [.package(path: "../../protocol/swift")],
    targets: [.target(name: "RemozioCore", dependencies: [.product(name: "RemozioProtocol", package: "swift")]), .testTarget(name: "RemozioCoreTests", dependencies: ["RemozioCore"])]
)
