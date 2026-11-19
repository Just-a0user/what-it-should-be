package mightymich.morphe.patches.com.whatsapp

import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.classDefByStrings
import app.morphe.patcher.patch.classDefForEach
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.iface.instruction.FiveRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.instruction.RegisterRangeInstruction
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference

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
 *     app accepts its own (patched) signature. (heuristic, own anchors)
 *  2. Force signature-mismatch guards to return success. (heuristic, own anchors)
 *  3. No-op Play Store install-source checks that gate registration. (heuristic, own anchors)
 *  4. Bypass local SHA-256 signature-hash string comparisons. (ported)
 *  5. Redirect com.android.vending / com.google.android.gms references to
 *     their microG-RE package equivalents, scoped to Intent.setPackage(...)
 *     call sites only. (ported, re-scoped after a crash found in v1.1.0 —
 *     see note below)
 *  6. Spoof the "X-Android-Cert" header sent on auth requests to a known
 *     Google-recognized client cert hash. (ported)
 *
 * Sections 4–6 are ported from BOPBOP-glitch/WhatsApp-share's LoginFix.kt
 * (https://github.com/BOPBOP-glitch/WhatsApp-share), which targeted
 * WhatsApp 2.26.27.4. Only the string/opcode-anchored parts of that patch
 * were ported — its two obfuscated-class-name fixes (a registration NPE in
 * class `LX/DFX;` method `A02`, and an installer-name null-guard) were left
 * out, since obfuscated short names like these are reassigned by WhatsApp's
 * build tooling on every release and almost certainly don't exist under the
 * same names on 2.26.45.93. Re-adding them would need fresh anchors found by
 * decompiling the actual 2.26.45.93 APK.
 *
 * Important limitation (still true after this port): section 6 can only
 * spoof a *self-reported* header value. It cannot fake a real, cryptographic
 * Play Integrity / SafetyNet attestation, which Google signs independently
 * and WhatsApp's backend may validate server-side regardless of what this
 * patch does on-device. If registration still fails after enabling this
 * patch, that's the likely reason — see the project's login-fix notes.
 *
 * This patch is DISABLED by default because:
 *  - It is only needed when registration / re-login fails on a patched APK.
 *  - It requires compatible microG-RE components for the GMS auth path.
 *  - Enabling it on a clean, properly signed APK is harmless but pointless.
 *
 * String anchors for sections 1–3 verified on 2.26.44.90. Sections 4–6 use
 * literal strings/API calls expected to be stable across nearby versions,
 * but have not been confirmed against an actual 2.26.45.93 APK.
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

        // ── 4. Local SHA-256 signature-hash string comparison bypass ─────────
        // Ported from BOPBOP-glitch/WhatsApp-share LoginFix.kt (targets
        // 2.26.27.4). This section matches two specific base64 SHA-256
        // strings embedded in WhatsApp's own code — believed to be the
        // expected Play Store / app signature hashes it compares against
        // locally — and forces the boolean comparison result that follows
        // them to "true" (match). Purely string/opcode based, no obfuscated
        // class or method names, so it should carry over across versions
        // as long as WhatsApp hasn't changed which hashes it embeds.
        run {
            val knownHashes = setOf(
                "8P1sW0EPJcslw7UzRsiXL64w-O50Ed-RBICtay1g24M",
                "-5INOBvuGyCT8n3I8T2ZTaYp3JGIfQUps1yaLcT0psI",
            )
            classDefForEach { def ->
                for (method in def.methods) {
                    if (method.name == "<clinit>") continue
                    val impl = method.implementation ?: continue
                    val instructions = impl.instructions.toList()

                    val matches = instructions.mapIndexedNotNull { index, instr ->
                        if (instr is ReferenceInstruction && instr.reference is StringReference) {
                            val str = (instr.reference as StringReference).string
                            if (str in knownHashes) {
                                var moveResultIdx = -1
                                var vZ = -1
                                for (i in index + 1 until minOf(index + 5, instructions.size)) {
                                    val next = instructions[i]
                                    if (next.opcode.name.startsWith("move-result")) {
                                        moveResultIdx = i
                                        vZ = (next as OneRegisterInstruction).registerA
                                        break
                                    }
                                }
                                if (moveResultIdx != -1) moveResultIdx to vZ else null
                            } else null
                        } else null
                    }

                    if (matches.isNotEmpty()) {
                        try {
                            val mutableMethod = mutableClassDefBy(def).methods.first {
                                it.name == method.name &&
                                    it.parameterTypes == method.parameterTypes &&
                                    it.returnType == method.returnType
                            }
                            matches.sortedByDescending { it.first }.forEach { (idx, vZ) ->
                                mutableMethod.addInstructions(idx + 1, "const/16 v$vZ, 0x1")
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }

        // ── 5. microG-RE package redirection ──────────────────────────────────
        // Rewrites literal references to the real Play Store / GMS package
        // names to the microG-RE equivalents, so that Intents the app builds
        // against "Google Play Services" or "the Play Store" actually
        // resolve to the installed microG-RE components instead of a
        // (possibly absent) real Google package.
        //
        // BOTH strings are scoped to Intent.setPackage(...) calls only. An
        // earlier version of this section (v1.1.0) rewrote "com.android.vending"
        // unconditionally, everywhere it appeared in the whole app, with no
        // filter at all — that string also shows up in unrelated code
        // (install-source checks, licensing, crash/ad SDKs, allow-lists), and
        // blindly rewriting it there caused a crash on launch. Scoping both
        // strings the same way (like the GMS half already was) removes that
        // risk entirely while keeping the only use case this section is
        // actually for: redirecting outgoing Intents.
        run {
            val redirectTargets = mapOf(
                "com.android.vending" to "app.revanced.android.vending",
                "com.google.android.gms" to "app.revanced.android.gms",
            )
            classDefForEach { def ->
                for (method in def.methods) {
                    val impl = method.implementation ?: continue
                    val instructions = impl.instructions.toList()

                    val matches = instructions.mapIndexedNotNull { index, instr ->
                        if (instr is ReferenceInstruction && instr.reference is StringReference) {
                            val str = (instr.reference as StringReference).string
                            val replacement = redirectTargets[str]
                            if (replacement != null) index to replacement else null
                        } else null
                    }
                    if (matches.isEmpty()) continue

                    try {
                        val mutableMethod = mutableClassDefBy(def).methods.first {
                            it.name == method.name &&
                                it.parameterTypes == method.parameterTypes &&
                                it.returnType == method.returnType
                        }
                        val mImpl = mutableMethod.implementation ?: continue
                        val mInstrs = mImpl.instructions.toList()

                        matches.sortedByDescending { it.first }.forEach { (idx, replacement) ->
                            // Only rewrite where the string feeds straight into
                            // Intent.setPackage(...) — require that call to show
                            // up within the next few instructions.
                            var isSetPackageCall = false
                            for (i in idx + 1 until minOf(idx + 6, mInstrs.size)) {
                                val next = mInstrs[i]
                                if (next is ReferenceInstruction && next.reference is MethodReference) {
                                    val ref = next.reference as MethodReference
                                    if (ref.name == "setPackage" &&
                                        ref.definingClass == "Landroid/content/Intent;"
                                    ) {
                                        isSetPackageCall = true
                                        break
                                    }
                                }
                            }
                            if (!isSetPackageCall) return@forEach

                            val instr = mInstrs.getOrNull(idx) as? OneRegisterInstruction
                                ?: return@forEach
                            mutableMethod.addInstructions(
                                idx + 1,
                                "const-string v${instr.registerA}, \"$replacement\"",
                            )
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }

        // ── 6. X-Android-Cert header spoof ────────────────────────────────────
        // Ported from the same source. WhatsApp/GMS auth requests attach an
        // "X-Android-Cert" HTTP header carrying the app's own signing
        // certificate SHA-1 hash — this is self-reported by the client, not
        // independently re-verified against the installed APK, so unlike a
        // real Play Integrity attestation it CAN be overridden client-side.
        // This forces that header's value to a known, Google-recognized
        // client certificate hash used throughout the microG ecosystem.
        // NOTE: this does not address a genuine Play Integrity / SafetyNet
        // check, if WhatsApp also performs one independently server-side —
        // see project notes on LoginFix for that limitation.
        run {
            val knownGoodCertHash = "38a0f7d505fe18fec64fbf343ecaaaf310dbd799"
            classDefForEach { def ->
                for (method in def.methods) {
                    val impl = method.implementation ?: continue
                    val instructions = impl.instructions.toList()

                    var certReg = -1
                    instructions.forEachIndexed { index, instr ->
                        if (instr is ReferenceInstruction && instr.reference is StringReference) {
                            if ((instr.reference as StringReference).string == "X-Android-Cert") {
                                val next = instructions.getOrNull(index + 1)
                                if (next is OneRegisterInstruction && next.opcode.name.startsWith("const-string")) {
                                    certReg = next.registerA
                                } else if (instr is OneRegisterInstruction) {
                                    certReg = instr.registerA
                                }
                            }
                        }
                    }

                    if (certReg != -1) {
                        try {
                            val mutableMethod = mutableClassDefBy(def).methods.first {
                                it.name == method.name &&
                                    it.parameterTypes == method.parameterTypes &&
                                    it.returnType == method.returnType
                            }
                            val mImpl = mutableMethod.implementation ?: continue
                            val mInstrs = mImpl.instructions.toList()

                            val matches = mInstrs.mapIndexedNotNull { index, instr ->
                                val ref = (instr as? ReferenceInstruction)?.reference?.toString()
                                if (ref == "Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V" &&
                                    instr.opcode.name.startsWith("invoke-virtual")
                                ) {
                                    val vD: Int
                                    val vE: Int
                                    if (instr is FiveRegisterInstruction) {
                                        vD = instr.registerD
                                        vE = instr.registerE
                                    } else if (instr is RegisterRangeInstruction) {
                                        vD = instr.startRegister + 1
                                        vE = instr.startRegister + 2
                                    } else {
                                        return@mapIndexedNotNull null
                                    }
                                    if (vD == certReg) index to vE else null
                                } else null
                            }

                            matches.sortedByDescending { it.first }.forEach { (idx, vE) ->
                                mutableMethod.addInstructions(idx, "const-string v$vE, \"$knownGoodCertHash\"")
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }

        // Soft success — anchors move between minor versions.
    }
}
