// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "AuthorityJournalExperiment", platforms: [.macOS(.v26)],
    products: [.executable(name: "authority-journal-experiment", targets: ["AuthorityJournalExperiment"])],
    targets: [.executableTarget(name: "AuthorityJournalExperiment")])
