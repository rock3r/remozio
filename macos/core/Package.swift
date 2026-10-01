// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioCore",
    platforms: [.macOS("26.0")],
    products: [.library(name: "RemozioCore", targets: ["RemozioCore"])],
    targets: [.target(name: "RemozioCore"), .testTarget(name: "RemozioCoreTests", dependencies: ["RemozioCore"])]
)
