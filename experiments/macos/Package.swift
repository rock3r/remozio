// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "RemozioMacExperiments",
    platforms: [.macOS("26.0")],
    products: [.executable(name: "remozio-xpc-probe", targets: ["XPCProbe"]), .executable(name: "remozio-presence-probe", targets: ["PresenceProbe"])],
    targets: [.executableTarget(name: "XPCProbe"), .executableTarget(name: "PresenceProbe")]
)
