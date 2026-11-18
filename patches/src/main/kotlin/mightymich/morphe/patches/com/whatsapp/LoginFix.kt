package mightymich.morphe.patches.com.whatsapp

import app.morphe.patcher.patch.classDefByStrings
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags

/**
 * Login Fix — Experimental login compatibility patch for re-signed APKs.
 *
 * Re-signed APKs (e.g. patched with Revanced / Morphe) have a different
 * certificate fingerprint than the Play Store original. WhatsApp validates the
 * APK signature during registration and sometimes during re-login. When
 * combined with microG-RE (which re-implements Google Play Services), the
 * signature-check path can also interact with the GMS auth token flow.
 *
 * Strategy:
 *  1. No-op APK certificate / package-signature verification methods so the
 *     app accepts its own (patched) signature.
 *  2. Force signature-mismatch guards to return success.
 *  3. No-op Play Store install-source checks that gate registration.
 *
 * This patch is DISABLED by default because:
 *  - It is only needed when registration / re-login fails on a patched APK.
 *  - It requires compatible microG-RE components for the GMS auth path.
 *  - Enabling it on a clean, properly signed APK is harmless but pointless.
 *
 * String anchors verified on 2.26.44.90.
 */
@Suppress("unused")
val loginFixPatch = patch(
    name = "Login Fix Expertenmodus",
    description = "Experimental login compatibility patch for a re-signed APK. " +
        "Requires compatible microG-RE components. Enable only if registration/login fails.",
    default = false,
) {
    compatibleWith(WhatsAppCompatibility.WHATSAPP)

    execute {
        // ── 1. APK / certificate signature verification ──────────────────────
        val signatureAnchors = listOf(
            "getPackageInfo",
            "signatures",
            "signingInfo",
            "checkSignature",
            "verifySignature",
            "signature_mismatch",
            "apk_tamper",
            "apk_modified",
            "certificate",
            "PackageVerifier",
            "AppSignature",
            "SignatureVerify",
            "SignatureCheck",
        )

        for (anchor in signatureAnchors) {
            val defs = try {
                classDefByStrings(anchor)
            } catch (_: Exception) {
                emptyList()
            }
            for (def in defs) {
                if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                val typeName = def.type
                if (typeName.startsWith("Landroid") ||
                    typeName.startsWith("Ljava") ||
                    typeName.startsWith("Lkotlin") ||
                    typeName.startsWith("Lcom/google")
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
                    val isCheckMethod = name.contains("check") ||
                        name.contains("verify") ||
                        name.contains("validate") ||
                        name.contains("sign") ||
                        name.contains("cert") ||
                        name.contains("tamper") ||
                        name.contains("match")

                    if (!isCheckMethod) continue

                    try {
                        when (method.returnType) {
                            "Z" -> method.returnEarly(true)   // "valid" = true
                            "V" -> method.returnEarly()
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }

        // ── 2. Install-source / Play Store origin checks ──────────────────────
        val installSourceAnchors = listOf(
            "getInstallerPackageName",
            "install_source",
            "com.android.vending",
            "installReferrer",
            "PlayStore",
        )

        for (anchor in installSourceAnchors) {
            val defs = try {
                classDefByStrings(anchor)
            } catch (_: Exception) {
                emptyList()
            }
            for (def in defs) {
                if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                val t = def.type
                if (t.startsWith("Landroid") || t.startsWith("Ljava") || t.startsWith("Lkotlin")) continue

                val clazz = try {
                    mutableClassDefBy(def)
                } catch (_: Exception) {
                    continue
                }

                for (method in clazz.methods) {
                    if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                    if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                    val impl = method.implementation ?: continue
                    if (impl.instructions.count() > 60) continue

                    val name = method.name.lowercase()
                    if (!name.contains("install") && !name.contains("store") &&
                        !name.contains("source") && !name.contains("vending")
                    ) continue

                    try {
                        when (method.returnType) {
                            "Z" -> method.returnEarly(true)
                            "V" -> method.returnEarly()
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }

        // ── 3. Registration gate booleans ─────────────────────────────────────
        val regAnchors = listOf(
            "registration_failed",
            "reg_error",
            "login_error",
            "RegistrationUtil",
            "RegistrationCheck",
            "canRegister",
            "isValidInstall",
        )

        for (anchor in regAnchors) {
            val defs = try {
                classDefByStrings(anchor)
            } catch (_: Exception) {
                emptyList()
            }
            for (def in defs) {
                if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                val t = def.type
                if (t.startsWith("Landroid") || t.startsWith("Ljava") || t.startsWith("Lkotlin")) continue

                val clazz = try {
                    mutableClassDefBy(def)
                } catch (_: Exception) {
                    continue
                }

                for (method in clazz.methods) {
                    if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                    if (method.returnType != "Z") continue
                    if (method.parameterTypes.isNotEmpty()) continue
                    val impl = method.implementation ?: continue
                    if (impl.instructions.count() > 40) continue

                    val name = method.name.lowercase()
                    if (!name.contains("can") && !name.contains("valid") &&
                        !name.contains("allowed") && !name.contains("permitted")
                    ) continue

                    try {
                        method.returnEarly(true)
                    } catch (_: Exception) {
                    }
                }
            }
        }

        // Soft success — anchors move between minor versions.
    }
}
