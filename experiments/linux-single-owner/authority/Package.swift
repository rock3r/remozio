// swift-tools-version: 6.2
import PackageDescription

// Disposable single-owner authority for the #988 PR2 experiment; never a protected Linux host authority.
let package = Package(
    name: "LinuxSingleOwnerAuthority",
    products: [.executable(name: "LinuxSingleOwnerAuthority", targets: ["LinuxSingleOwnerAuthority"])],
    dependencies: [
        .package(path: "../../linux-approval-command"),
        .package(path: "../../../host/shared-core"),
        .package(path: "../../../protocol/swift"),
        .package(url: "https://github.com/apple/swift-crypto.git", "4.5.1"..."5.0.1"),
    ],
    targets: [
        .target(name: "CSingleOwnerAuthority"),
        .executableTarget(name: "LinuxSingleOwnerAuthority", dependencies: [
            "CSingleOwnerAuthority",
            .product(name: "LinuxApprovalFixtureCore", package: "linux-approval-command"),
            .product(name: "RemozioHostCore", package: "shared-core"),
            .product(name: "RemozioProtocol", package: "swift"),
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
    ]
)
