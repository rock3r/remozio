// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioCore",
    platforms: [.macOS("26.0")],
    products: [.library(name: "RemozioCore", targets: ["RemozioCore"])],
    dependencies: [.package(path: "../../protocol/swift"), .package(url: "https://github.com/airsidemobile/JOSESwift.git", exact: "3.0.0")],
    targets: [.target(name: "RemozioMach"), .target(name: "RemozioCore", dependencies: ["RemozioMach", .product(name: "RemozioProtocol", package: "swift"), .product(name: "JOSESwift", package: "JOSESwift")], linkerSettings: [.linkedLibrary("bsm")]), .testTarget(name: "RemozioCoreTests", dependencies: ["RemozioCore", "RemozioMach"], resources: [.copy("Fixtures")])]
)
