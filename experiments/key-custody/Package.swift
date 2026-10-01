// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioKeyCustodyExperiment",
    platforms: [.macOS("26.0")],
    products: [.executable(name: "remozio-key-custody-probe", targets: ["KeyCustodyProbe"])],
    targets: [.executableTarget(name: "KeyCustodyProbe")]
)
