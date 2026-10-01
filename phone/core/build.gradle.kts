plugins { kotlin("jvm") }

kotlin { jvmToolchain(21) }

dependencies {
    implementation(project(":protocol-kotlin"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.11.0")
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
}

val capture = rootProject.layout.projectDirectory.file("android/app/src/debug/res/raw/sample_command.cbor")
tasks.withType<Test>().configureEach {
    useJUnit()
    val historyVectors = rootProject.layout.projectDirectory.file("protocol/vectors/audit-history-status-v1.json")
    inputs.file(historyVectors)
    systemProperty("remozio.test.auditHistoryVectors", historyVectors.asFile.absolutePath)
    inputs.file(capture)
    systemProperty("remozio.test.commandCapture", capture.asFile.absolutePath)
}

tasks.test { exclude("**/ApprovalFlowTest.class", "**/AuditFlowTest.class") }

tasks.register<Test>("approvalFlowTest") {
    description = "Runs synthetic Swift and Kotlin approval and audit peers on a Mac."
    group = "verification"
    dependsOn(tasks.testClasses)
    testClassesDirs = sourceSets.test.get().output.classesDirs
    classpath = sourceSets.test.get().runtimeClasspath
    filter {
        includeTestsMatching("dev.remozio.phone.requests.ApprovalFlowTest")
        includeTestsMatching("dev.remozio.phone.audit.AuditFlowTest")
    }
    val peer = rootProject.layout.projectDirectory.file(
        ".build/approval-flow/ApprovalFlowPeer")
    inputs.file(peer)
    systemProperty("remozio.test.swiftPeer", peer.asFile.absolutePath)
    val auditPeer = rootProject.layout.projectDirectory.file(".build/approval-flow/AuditFlowPeer")
    inputs.file(auditPeer)
    systemProperty("remozio.test.auditPeer", auditPeer.asFile.absolutePath)
}
