// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "ApprovalFlowExperiment",
    platforms: [.macOS("26.0")],
    dependencies: [.package(path: "../../protocol/swift"), .package(path: "../../macos/core")],
    targets: [.executableTarget(name: "TLSPeer"), .executableTarget(name: "HPKEPeer"), .executableTarget(name: "ApprovalFlowPeer", dependencies: [
        .product(name: "RemozioProtocol", package: "swift"),
        .product(name: "RemozioCore", package: "core"),
    ]), .executableTarget(name: "AuditFlowPeer", dependencies: [
        .product(name: "RemozioProtocol", package: "swift"),
        .product(name: "RemozioCore", package: "core"),
    ])]
)
