package mightymich.morphe.patches.com.whatsapp

import app.morphe.patcher.patch.booleanOption
import app.morphe.patcher.patch.classDefByStrings
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags

/**
 * Anti Detector — Minimize WhatsApp's ability to detect that the APK has been
 * modified, that the device is rooted, or that a framework hook (Xposed / LSPosed)
 * is active.
 *
 * Four layers:
 *  1. APK integrity / modified-APK detection  → spoof as unmodified
 *  2. Root detection  → spoof as not rooted
 *  3. Xposed / LSPosed / hook framework detection  → spoof as clean
 *  4. Play Integrity / SafetyNet attestation  → no-op / spoof MEETS_BASIC_INTEGRITY
 *
 * None of these patches affect server-side signals (IP reputation, usage patterns,
 * message timing, feature usage). They target only the in-app self-checks the
 * client performs and reports.
 *
 * String anchors verified against 2.26.44.90; soft-success throughout.
 */
@Suppress("unused")
val antiDetectorPatch = patch(
    name = "Anti Detector",
    description = "Spoof APK-integrity, root, Xposed, and Play Integrity checks so " +
        "WhatsApp reports a clean, unmodified install to its own telemetry and to its server.",
    default = true,
) {
    compatibleWith(WhatsAppCompatibility.WHATSAPP)

    val spoofRootDetection by booleanOption(
        key = "spoof_root",
        default = true,
        title = "Spoof root detection",
        description = "Make the app believe the device is not rooted.",
    )

    val spoofXposed by booleanOption(
        key = "spoof_xposed",
        default = true,
        title = "Spoof Xposed / LSPosed detection",
        description = "Make the app believe no hook framework is active.",
    )

    val spoofPlayIntegrity by booleanOption(
        key = "spoof_play_integrity",
        default = true,
        title = "Spoof Play Integrity / SafetyNet",
        description = "No-op Play Integrity / SafetyNet API calls and force pass result.",
    )

    execute {

        // ── 1. APK integrity / tamper detection ──────────────────────────────
        val integrityAnchors = listOf(
            "apk_tamper",
            "apk_modified",
            "apkModified",
            "apkTamper",
            "checkApkIntegrity",
            "verifyApkIntegrity",
            "AppIntegrityChecker",
            "IntegrityChecker",
            "tamper_detection",
            "TamperDetection",
            "isModified",
            "isPatched",
            "isDebuggable",
            "debuggable",
            "ALLOW_BACKUP",
            "INSTALL_PACKAGES",
            "signature_check",
            "CertificatePin",
        )

        for (anchor in integrityAnchors) {
            val defs = try {
                classDefByStrings(anchor)
            } catch (_: Exception) {
                emptyList()
            }
            for (def in defs) {
                if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                val t = def.type
                if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                    t.startsWith("Lkotlin") || t.startsWith("Lcom/google")
                ) continue

                val clazz = try {
                    mutableClassDefBy(def)
                } catch (_: Exception) {
                    continue
                }

                for (method in clazz.methods) {
                    if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                    if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                    val impl = method.implementation ?: continue
                    val count = impl.instructions.count()
                    if (count < 2 || count > 160) continue

                    val name = method.name.lowercase()
                    val relevant = name.contains("tamper") || name.contains("integ") ||
                        name.contains("modif") || name.contains("patch") ||
                        name.contains("check") || name.contains("verify") ||
                        name.contains("valid") || name.contains("debug") ||
                        name.contains("sign") || name.contains("cert")
                    if (!relevant) continue

                    try {
                        when (method.returnType) {
                            // "is modified/tampered?" → false
                            "Z" -> method.returnEarly(false)
                            // void check methods → become no-ops
                            "V" -> method.returnEarly()
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }

        // ── 2. Root detection ─────────────────────────────────────────────────
        if (spoofRootDetection == true) {
            val rootAnchors = listOf(
                "isRooted",
                "isDeviceRooted",
                "RootDetect",
                "root_detect",
                "RootChecker",
                "/system/bin/su",
                "/system/xbin/su",
                "com.topjohnwu.magisk",
                "com.kingroot.kinguser",
                "eu.chainfire.supersu",
                "RootBeer",
                "busybox",
                "which su",
                "checkForBinary",
                "findBinary",
            )

            for (anchor in rootAnchors) {
                val defs = try {
                    classDefByStrings(anchor)
                } catch (_: Exception) {
                    emptyList()
                }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                        t.startsWith("Lkotlin") || t.startsWith("Lcom/google")
                    ) continue

                    val clazz = try {
                        mutableClassDefBy(def)
                    } catch (_: Exception) {
                        continue
                    }

                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        val count = impl.instructions.count()
                        if (count < 2 || count > 120) continue

                        val name = method.name.lowercase()
                        val relevant = name.contains("root") || name.contains("su") ||
                            name.contains("check") || name.contains("detect") ||
                            name.contains("find") || name.contains("exist")
                        if (!relevant) continue

                        try {
                            when (method.returnType) {
                                "Z" -> method.returnEarly(false)   // "is rooted?" → false
                                "V" -> method.returnEarly()
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }

        // ── 3. Xposed / LSPosed / hook-framework detection ───────────────────
        if (spoofXposed == true) {
            val xposedAnchors = listOf(
                "de.robv.android.xposed",
                "XposedBridge",
                "XposedHelper",
                "XposedMod",
                "xposed",
                "lsposed",
                "LSPosedBridge",
                "EdXp",
                "isXposedActive",
                "XposedChecker",
                "isHooked",
                "hookMethod",
                "loadedModules",
                "XPOSED_BRIDGE_VERSION",
                "io.github.lsposed",
            )

            for (anchor in xposedAnchors) {
                val defs = try {
                    classDefByStrings(anchor)
                } catch (_: Exception) {
                    emptyList()
                }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                        t.startsWith("Lkotlin") || t.startsWith("Lcom/google")
                    ) continue

                    val clazz = try {
                        mutableClassDefBy(def)
                    } catch (_: Exception) {
                        continue
                    }

                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        val count = impl.instructions.count()
                        if (count < 2 || count > 100) continue

                        val name = method.name.lowercase()
                        val relevant = name.contains("xposed") || name.contains("hook") ||
                            name.contains("lsposed") || name.contains("check") ||
                            name.contains("detect") || name.contains("active") ||
                            name.contains("loaded")
                        if (!relevant) continue

                        try {
                            when (method.returnType) {
                                "Z" -> method.returnEarly(false)   // "is Xposed active?" → false
                                "V" -> method.returnEarly()
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }

        // ── 4. Play Integrity / SafetyNet ─────────────────────────────────────
        if (spoofPlayIntegrity == true) {
            val integrityApiAnchors = listOf(
                "IntegrityManager",
                "IntegrityServiceConnection",
                "SafetyNetClient",
                "SafetyNet",
                "safetynet",
                "MEETS_BASIC_INTEGRITY",
                "MEETS_DEVICE_INTEGRITY",
                "play_integrity",
                "PlayIntegrity",
                "AttestationResult",
                "DeviceIntegrity",
                "AppIntegrity",
                "AccountDetails",
                "StandardIntegrityToken",
                "requestIntegrityVerification",
                "requestAttestation",
            )

            for (anchor in integrityApiAnchors) {
                val defs = try {
                    classDefByStrings(anchor)
                } catch (_: Exception) {
                    emptyList()
                }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                        t.startsWith("Lkotlin")
                    ) continue

                    val clazz = try {
                        mutableClassDefBy(def)
                    } catch (_: Exception) {
                        continue
                    }

                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        val count = impl.instructions.count()
                        if (count < 2 || count > 160) continue

                        val name = method.name.lowercase()
                        val relevant = name.contains("integrity") || name.contains("attest") ||
                            name.contains("safety") || name.contains("request") ||
                            name.contains("verify") || name.contains("check") ||
                            name.contains("token")
                        if (!relevant) continue

                        try {
                            when (method.returnType) {
                                "Z" -> method.returnEarly(true)   // "passes integrity?" → true
                                "V" -> method.returnEarly()
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }

        // Soft success throughout — missing anchors do not fail the patch session.
    }
}
