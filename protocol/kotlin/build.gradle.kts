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
    inputs.files(vectors, actionVectors, lifecycleVectors)
    systemProperty("remozio.lifecycleVectors", lifecycleVectors.asFile.absolutePath)
    systemProperty("remozio.actionVectors", actionVectors.asFile.absolutePath)
    systemProperty("remozio.vectors", vectors.asFile.absolutePath)
}
