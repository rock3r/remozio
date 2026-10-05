import Foundation

// Compile this fixture with the production DynamicCodeValidation source.
guard CommandLine.arguments.count == 2 || CommandLine.arguments.count == 3 else {
    exit(64)
}
if CommandLine.arguments.count == 3 {
    FileHandle.standardOutput.write(Data("ready\n".utf8))
    guard FileHandle.standardInput.readData(ofLength: 1).count == 1 else { exit(64) }
}
do {
    try DynamicCodeValidation.validateSelf(requirement: CommandLine.arguments[1])
    print("accepted")
} catch {
    print("rejected")
    exit(1)
}
