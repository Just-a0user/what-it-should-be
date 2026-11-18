group = "mightymich.morphe"

patches {
    about {
        name = "WhatsApp Patches"
        description = "All-in-one patch for WhatsApp 2.26.45.93: login fix, keep deleted messages, view-once unlock, anti-detection, anti-revoke, remove Meta AI, limit telemetry"
        source = "git@github.com:Just-a0user/what-it-should-be.git"
        author = "Just-a0user"
        contact = "na"
        website = "https://github.com/Just-a0user/what-it-should-be"
        license = "GPLv3"
    }
}

// Separate configuration so gson is available at runtime for the
// generatePatchesList task but never bundled into the APK.
val patchListGeneratorClasspath = configurations.create("patchListGeneratorClasspath")

dependencies {
    compileOnly(libs.gson)
    patchListGeneratorClasspath(libs.gson)
}

tasks {
    register<JavaExec>("generatePatchesList") {
        description = "Build patch with patch list"

        dependsOn(build)

        classpath = sourceSets["main"].runtimeClasspath + patchListGeneratorClasspath
        mainClass.set("util.PatchListGeneratorKt")
    }

    // Used by gradle-semantic-release-plugin.
    publish {
        dependsOn("generatePatchesList")
    }
}
