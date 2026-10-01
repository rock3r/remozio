plugins { kotlin("jvm") }

kotlin { jvmToolchain(21) }

dependencies {
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
}

tasks.test {
    useJUnit()
    val vectors = rootProject.layout.projectDirectory.file("protocol/vectors/cbor-subset-v1.json")
    val actionVectors = rootProject.layout.projectDirectory.file("protocol/vectors/action-policy-v1.json")
    val lifecycleVectors = rootProject.layout.projectDirectory.file("protocol/vectors/lifecycle-v1.json")
    val signingVectors = rootProject.layout.projectDirectory.file("protocol/vectors/signing-input-v1.json")
    val signatureVectors = rootProject.layout.projectDirectory.file("protocol/vectors/approval-signatures-v1.json")
    val decisionVectors = rootProject.layout.projectDirectory.file("protocol/vectors/decision-payload-v1.json")
    val requestVectors = rootProject.layout.projectDirectory.file("protocol/vectors/issued-request-v1.json")
    val statusVectors = rootProject.layout.projectDirectory.file("protocol/vectors/request-status-v1.json")
    systemProperty("remozio.statusVectors", statusVectors.asFile.absolutePath)
    val commandVectors = rootProject.layout.projectDirectory.file("protocol/vectors/command-capture-v1.json")
    systemProperty("remozio.commandVectors", commandVectors.asFile.absolutePath)
    inputs.files(statusVectors, commandVectors, vectors, actionVectors, lifecycleVectors, signingVectors, signatureVectors, decisionVectors, requestVectors)
    systemProperty("remozio.requestVectors", requestVectors.asFile.absolutePath)
    systemProperty("remozio.decisionVectors", decisionVectors.asFile.absolutePath)
    systemProperty("remozio.signatureVectors", signatureVectors.asFile.absolutePath)
    systemProperty("remozio.signingVectors", signingVectors.asFile.absolutePath)
    systemProperty("remozio.lifecycleVectors", lifecycleVectors.asFile.absolutePath)
    systemProperty("remozio.actionVectors", actionVectors.asFile.absolutePath)
    systemProperty("remozio.vectors", vectors.asFile.absolutePath)
}
