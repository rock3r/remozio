// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioKeyCustodyExperiment",
    platforms: [.macOS("26.0")],
    products: [.executable(name: "remozio-key-custody-probe", targets: ["KeyCustodyProbe"])],
    dependencies: [.package(path: "../../macos/core"), .package(path: "../../protocol/swift")],
    targets: [.executableTarget(name: "KeyCustodyProbe"),
              .executableTarget(name: "EnclaveTLSProbe", dependencies: [.product(name: "RemozioCore", package: "core"),
                  .product(name: "RemozioProtocol", package: "swift")])]
)
