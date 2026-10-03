// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioCore",
    platforms: [.macOS("26.0")],
    products: [.library(name: "RemozioCore", targets: ["RemozioCore"])],
    dependencies: [.package(path: "../../protocol/swift"), .package(url: "https://github.com/airsidemobile/JOSESwift.git", exact: "3.0.0")],
    targets: [.target(name: "RemozioCore", dependencies: [.product(name: "RemozioProtocol", package: "swift"), .product(name: "JOSESwift", package: "JOSESwift")]), .testTarget(name: "RemozioCoreTests", dependencies: ["RemozioCore"], resources: [.copy("Fixtures")])]
)
