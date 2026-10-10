import RemozioCore

@main
struct FrontendMain {
    static func main() {
        #if DEBUG
        let domain = "dev.remozio.mac.debug"
        #else
        let domain = "dev.remozio.mac"
        #endif
        CommandFrontendMain.run(count: CommandLine.argc, vector: CommandLine.unsafeArgv, preferencesDomain: domain).finish()
    }
}
