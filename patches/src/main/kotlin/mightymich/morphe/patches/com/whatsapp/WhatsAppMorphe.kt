package mightymich.morphe.patches.com.whatsapp

import app.morphe.patcher.patch.booleanOption
import app.morphe.patcher.patch.classDefByStrings
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags

/**
 * WhatsApp Morphe — All-in-one patch bundle for 2.26.45.93.
 *
 * Features (all togglable):
 *  1. Login Fix — bypass signature/cert checks that block SMS code on re-signed APKs (microG-RE)
 *  2. Keep Deleted Messages — client never wipes messages deleted "for everyone"
 *  3. View Once Unlock — save and re-open view-once photos/videos
 *  4. Anti Detector — spoof APK integrity, root, Xposed, Play Integrity checks
 *  5. Anti Revoke Expertenmodus — stop others' "delete for everyone" from reaching your client
 *  6. Remove Meta AI — hide the Meta AI FAB/pill and hub entry points
 *  7. Usage Data — no-op WhatsApp analytics and telemetry calls
 *
 * All sections use soft-success: missing anchors skip silently, the patch
 * still installs. String anchors verified against 2.26.44.90 / 2.26.45.93.
 */
@Suppress("unused")
val whatsAppMorphePatch = patch(
    name = "WhatsApp Morphe",
    description = "All-in-one patch: login fix, keep deleted messages, view-once unlock, " +
        "anti-detection, anti-revoke, remove Meta AI, limit telemetry.",
    default = true,
) {
    compatibleWith(WhatsAppCompatibility.WHATSAPP)

    // ─── options ──────────────────────────────────────────────────────────────

    val loginFix by booleanOption(
        key = "login_fix",
        default = true,
        title = "Login Fix Expertenmodus",
        description = "Bypass APK signature / cert checks that block SMS verification on " +
            "re-signed APKs. Requires microG-RE. Enable if registration / login fails.",
    )

    val keepDeleted by booleanOption(
        key = "keep_deleted",
        default = true,
        title = "Keep deleted messages",
        description = "Show messages that were deleted for everyone. Client-side only.",
    )

    val viewOnce by booleanOption(
        key = "view_once",
        default = true,
        title = "View once media",
        description = "Allow reopening and saving view-once photos and videos.",
    )

    val antiDetect by booleanOption(
        key = "anti_detect",
        default = true,
        title = "Anti Detector",
        description = "Spoof APK-integrity, root, Xposed and Play Integrity checks.",
    )

    val spoofRoot by booleanOption(
        key = "spoof_root",
        default = true,
        title = "  ↳ Spoof root detection",
        description = "Make the app believe the device is not rooted.",
    )

    val spoofXposed by booleanOption(
        key = "spoof_xposed",
        default = true,
        title = "  ↳ Spoof Xposed / LSPosed detection",
        description = "Make the app believe no hook framework is active.",
    )

    val spoofPlayIntegrity by booleanOption(
        key = "spoof_play_integrity",
        default = true,
        title = "  ↳ Spoof Play Integrity / SafetyNet",
        description = "No-op Play Integrity / SafetyNet API calls and force pass result.",
    )

    val antiRevoke by booleanOption(
        key = "anti_revoke",
        default = true,
        title = "Anti Revoke Expertenmodus",
        description = "Prevent others from deleting their messages or statuses on your client.",
    )

    val antiRevokeStatuses by booleanOption(
        key = "anti_revoke_statuses",
        default = true,
        title = "  ↳ Block status revokes",
        description = "Also prevent others from deleting their status/story updates.",
    )

    val removeMetaAI by booleanOption(
        key = "remove_meta_ai",
        default = true,
        title = "Remove Meta AI",
        description = "Hide the Meta AI FAB/pill on the home screen and hub entry points.",
    )

    val metaAIAggressive by booleanOption(
        key = "meta_ai_aggressive",
        default = false,
        title = "  ↳ Aggressive Meta AI hide",
        description = "Force extra boolean gates in Meta-AI classes. Leave off unless FAB still shows.",
    )

    val telemetry by booleanOption(
        key = "telemetry",
        default = true,
        title = "Usage data",
        description = "Limit diagnostic and analytics data WhatsApp sends.",
    )

    // ─── helpers ──────────────────────────────────────────────────────────────

    execute {

        // ══════════════════════════════════════════════════════════════════════
        // 1. LOGIN FIX
        // ══════════════════════════════════════════════════════════════════════
        if (loginFix == true) {

            // 1a. APK / certificate signature verification
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
                // 2.26.45.x additions
                "apkCertificate",
                "verifyCert",
                "certFingerprint",
            )

            for (anchor in signatureAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                        t.startsWith("Lkotlin") || t.startsWith("Lcom/google")
                    ) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        val count = impl.instructions.count()
                        if (count < 2 || count > 120) continue
                        val name = method.name.lowercase()
                        if (!name.contains("check") && !name.contains("verify") &&
                            !name.contains("validate") && !name.contains("sign") &&
                            !name.contains("cert") && !name.contains("tamper") &&
                            !name.contains("match")
                        ) continue
                        try {
                            when (method.returnType) {
                                "Z" -> method.returnEarly(true)   // "valid signature?" → true
                                "V" -> method.returnEarly()
                            }
                        } catch (_: Exception) {}
                    }
                }
            }

            // 1b. Install-source / Play Store origin checks
            val installSourceAnchors = listOf(
                "getInstallerPackageName",
                "install_source",
                "com.android.vending",
                "installReferrer",
                "PlayStore",
            )
            for (anchor in installSourceAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") || t.startsWith("Lkotlin")) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
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
                        } catch (_: Exception) {}
                    }
                }
            }

            // 1c. Registration gate booleans
            //     "verification code not sent" on re-signed APKs often comes from a
            //     canRegister / isValidInstall gate returning false before the SMS
            //     request is even dispatched. Force them all true.
            val regAnchors = listOf(
                "registration_failed",
                "reg_error",
                "login_error",
                "RegistrationUtil",
                "RegistrationCheck",
                "canRegister",
                "isValidInstall",
                // 2.26.45.x — additional SMS dispatch gate
                "sms_code_dispatch",
                "smsSendAllowed",
                "registrationGate",
                "RegFlowValidator",
            )
            for (anchor in regAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") || t.startsWith("Lkotlin")) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (method.returnType != "Z") continue
                        if (method.parameterTypes.isNotEmpty()) continue
                        val impl = method.implementation ?: continue
                        if (impl.instructions.count() > 40) continue
                        val name = method.name.lowercase()
                        if (!name.contains("can") && !name.contains("valid") &&
                            !name.contains("allowed") && !name.contains("permitted") &&
                            !name.contains("send") && !name.contains("dispatch") &&
                            !name.contains("gate")
                        ) continue
                        try { method.returnEarly(true) } catch (_: Exception) {}
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // 2. KEEP DELETED MESSAGES
        // ══════════════════════════════════════════════════════════════════════
        if (keepDeleted == true) {

            val revokeAnchors = listOf(
                "StandardRevokePreProcessor.kt",
                "RevokePreProcessor.kt",
                "RevokeEditProcessor.kt",
                "RevokeEditProcessor",
                "FMessageRevokedFactory",
                "UserActionsMessageDeletion/userActionRevokeMessages",
                "/processMessage revoked message ",
                "msgstore/revoke: Failed to re-insert revoked message:",
            )
            for (anchor in revokeAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        val n = impl.instructions.count()
                        if (n < 3 || n > 200) continue
                        val mname = method.name.lowercase()
                        val isRevokeMethod = mname.contains("revoke") ||
                            mname.contains("delete") ||
                            mname.contains("process") ||
                            mname.contains("handle") ||
                            mname.contains("apply") ||
                            mname.contains("insert") ||
                            mname.contains("dispatch")
                        if (!isRevokeMethod) continue
                        try {
                            when (method.returnType) {
                                "V" -> method.returnEarly()
                                "Z" -> method.returnEarly(false)
                            }
                        } catch (_: Exception) {}
                    }
                }
            }

            val flagAnchors = listOf(
                "isRevokeMessage",
                "messageIsRevoke",
                ", isRevoked=",
                "FMessageRevoked",
                "ConversationRowRevoked.kt",
                "ConversationRowAdminRevoked.kt",
            )
            val flagNames = setOf("isRevokeMessage", "isRevoked", "messageIsRevoke", "isDeleted")
            val seen = mutableSetOf<String>()
            for (anchor in flagAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (!seen.add(def.type)) continue
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Landroidx") ||
                        t.startsWith("Ljava") || t.startsWith("Lkotlin")
                    ) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (method.returnType != "Z") continue
                        if (method.parameterTypes.isNotEmpty()) continue
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (method.name !in flagNames) continue
                        try { method.returnEarly(false) } catch (_: Exception) {}
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // 3. VIEW ONCE UNLOCK
        // ══════════════════════════════════════════════════════════════════════
        if (viewOnce == true) {
            val markers = listOf("view_once", "view once", "ViewOnce", "ephemeral_view_once")
            for (marker in markers) {
                val defs = try { classDefByStrings(marker) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (method.returnType != "Z") continue
                        if (method.parameterTypes.isNotEmpty()) continue
                        val impl = method.implementation ?: continue
                        if (impl.instructions.count() > 40) continue
                        val text = impl.instructions.joinToString("\n") { it.toString() }
                        if (!text.contains("once", ignoreCase = true) && !text.contains(marker)) continue
                        val n = method.name.lowercase()
                        if (!n.contains("view") && !n.contains("once") && !n.contains("ephemeral")) continue
                        try { method.returnEarly(false) } catch (_: Exception) {}
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // 4. ANTI DETECTOR
        // ══════════════════════════════════════════════════════════════════════
        if (antiDetect == true) {

            // 4a. APK integrity / tamper detection
            val integrityAnchors = listOf(
                "apk_tamper", "apk_modified", "apkModified", "apkTamper",
                "checkApkIntegrity", "verifyApkIntegrity", "AppIntegrityChecker",
                "IntegrityChecker", "tamper_detection", "TamperDetection",
                "isModified", "isPatched", "isDebuggable", "debuggable",
                "ALLOW_BACKUP", "INSTALL_PACKAGES", "signature_check", "CertificatePin",
            )
            for (anchor in integrityAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                        t.startsWith("Lkotlin") || t.startsWith("Lcom/google")
                    ) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        val count = impl.instructions.count()
                        if (count < 2 || count > 160) continue
                        val name = method.name.lowercase()
                        if (!name.contains("tamper") && !name.contains("integ") &&
                            !name.contains("modif") && !name.contains("patch") &&
                            !name.contains("check") && !name.contains("verify") &&
                            !name.contains("valid") && !name.contains("debug") &&
                            !name.contains("sign") && !name.contains("cert")
                        ) continue
                        try {
                            when (method.returnType) {
                                "Z" -> method.returnEarly(false)   // "is modified?" → false
                                "V" -> method.returnEarly()
                            }
                        } catch (_: Exception) {}
                    }
                }
            }

            // 4b. Root detection
            if (spoofRoot == true) {
                val rootAnchors = listOf(
                    "isRooted", "isDeviceRooted", "RootDetect", "root_detect", "RootChecker",
                    "/system/bin/su", "/system/xbin/su", "com.topjohnwu.magisk",
                    "com.kingroot.kinguser", "eu.chainfire.supersu", "RootBeer",
                    "busybox", "which su", "checkForBinary", "findBinary",
                )
                for (anchor in rootAnchors) {
                    val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                    for (def in defs) {
                        if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                        val t = def.type
                        if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                            t.startsWith("Lkotlin") || t.startsWith("Lcom/google")
                        ) continue
                        val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                        for (method in clazz.methods) {
                            if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                            if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                            val impl = method.implementation ?: continue
                            val count = impl.instructions.count()
                            if (count < 2 || count > 120) continue
                            val name = method.name.lowercase()
                            if (!name.contains("root") && !name.contains("su") &&
                                !name.contains("check") && !name.contains("detect") &&
                                !name.contains("find") && !name.contains("exist")
                            ) continue
                            try {
                                when (method.returnType) {
                                    "Z" -> method.returnEarly(false)
                                    "V" -> method.returnEarly()
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }

            // 4c. Xposed / LSPosed / hook-framework detection
            if (spoofXposed == true) {
                val xposedAnchors = listOf(
                    "de.robv.android.xposed", "XposedBridge", "XposedHelper", "XposedMod",
                    "xposed", "lsposed", "LSPosedBridge", "EdXp", "isXposedActive",
                    "XposedChecker", "isHooked", "hookMethod", "loadedModules",
                    "XPOSED_BRIDGE_VERSION", "io.github.lsposed",
                )
                for (anchor in xposedAnchors) {
                    val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                    for (def in defs) {
                        if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                        val t = def.type
                        if (t.startsWith("Landroid") || t.startsWith("Ljava") ||
                            t.startsWith("Lkotlin") || t.startsWith("Lcom/google")
                        ) continue
                        val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                        for (method in clazz.methods) {
                            if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                            if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                            val impl = method.implementation ?: continue
                            val count = impl.instructions.count()
                            if (count < 2 || count > 100) continue
                            val name = method.name.lowercase()
                            if (!name.contains("xposed") && !name.contains("hook") &&
                                !name.contains("lsposed") && !name.contains("check") &&
                                !name.contains("detect") && !name.contains("active") &&
                                !name.contains("loaded")
                            ) continue
                            try {
                                when (method.returnType) {
                                    "Z" -> method.returnEarly(false)
                                    "V" -> method.returnEarly()
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }

            // 4d. Play Integrity / SafetyNet
            if (spoofPlayIntegrity == true) {
                val integrityApiAnchors = listOf(
                    "IntegrityManager", "IntegrityServiceConnection", "SafetyNetClient",
                    "SafetyNet", "safetynet", "MEETS_BASIC_INTEGRITY", "MEETS_DEVICE_INTEGRITY",
                    "play_integrity", "PlayIntegrity", "AttestationResult", "DeviceIntegrity",
                    "AppIntegrity", "AccountDetails", "StandardIntegrityToken",
                    "requestIntegrityVerification", "requestAttestation",
                )
                for (anchor in integrityApiAnchors) {
                    val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                    for (def in defs) {
                        if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                        val t = def.type
                        if (t.startsWith("Landroid") || t.startsWith("Ljava") || t.startsWith("Lkotlin")) continue
                        val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                        for (method in clazz.methods) {
                            if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                            if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                            val impl = method.implementation ?: continue
                            val count = impl.instructions.count()
                            if (count < 2 || count > 160) continue
                            val name = method.name.lowercase()
                            if (!name.contains("integrity") && !name.contains("attest") &&
                                !name.contains("safety") && !name.contains("request") &&
                                !name.contains("verify") && !name.contains("check") &&
                                !name.contains("token")
                            ) continue
                            try {
                                when (method.returnType) {
                                    "Z" -> method.returnEarly(true)   // "passes integrity?" → true
                                    "V" -> method.returnEarly()
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // 5. ANTI REVOKE EXPERTENMODUS
        // ══════════════════════════════════════════════════════════════════════
        if (antiRevoke == true) {

            // 5a. Outgoing revoke-ACK / confirmation methods
            val ackAnchors = listOf(
                "sendRevokeAck", "revokeAck", "revoke_ack", "RevokeAck",
                "processRevokeAck", "handleRevokeConfirm", "confirmRevoke",
                "RevokeConfirmProcessor",
                "msgstore/revoke: Failed to re-insert revoked message:",
                "UserActionsMessageDeletion/userActionRevokeMessages",
                "/processMessage revoked message ",
            )
            for (anchor in ackAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Landroidx") ||
                        t.startsWith("Ljava") || t.startsWith("Lkotlin")
                    ) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        if (impl.instructions.count() < 2 || impl.instructions.count() > 180) continue
                        val name = method.name.lowercase()
                        if (!name.contains("ack") && !name.contains("confirm") &&
                            !name.contains("revoke") && !name.contains("delete") &&
                            !name.contains("process") && !name.contains("send") &&
                            !name.contains("handle")
                        ) continue
                        try {
                            when (method.returnType) {
                                "V" -> method.returnEarly()
                                "Z" -> method.returnEarly(false)
                            }
                        } catch (_: Exception) {}
                    }
                }
            }

            // 5b. Pending revoke queue drain
            val queueAnchors = listOf(
                "RevokeQueue", "pendingRevoke", "pending_revoke",
                "PendingRevokeProcessor", "drainRevoke", "flushRevoke",
            )
            for (anchor in queueAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val t = def.type
                    if (t.startsWith("Landroid") || t.startsWith("Ljava") || t.startsWith("Lkotlin")) continue
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        if (method.returnType != "V") continue
                        val impl = method.implementation ?: continue
                        val count = impl.instructions.count()
                        if (count < 1 || count > 150) continue
                        // Only touch methods whose own name suggests the queue-drain
                        // path — matching the class by a pooled string is not enough,
                        // since unrelated methods (constructors, field init, logging)
                        // can share a class with the anchor string and must not be
                        // no-op'd. Doing so previously caused a startup crash.
                        val name = method.name.lowercase()
                        if (!name.contains("revoke") && !name.contains("pending") &&
                            !name.contains("drain") && !name.contains("flush") &&
                            !name.contains("queue") && !name.contains("process")
                        ) continue
                        try { method.returnEarly() } catch (_: Exception) {}
                    }
                }
            }

            // 5c. Status / story revoke delivery
            if (antiRevokeStatuses == true) {
                val statusRevokeAnchors = listOf(
                    "StatusRevoke", "status_revoke", "StoryRevoke", "story_revoke",
                    "revokeStatus", "deleteStatus", "StatusDelete", "StatusDeleteProcessor",
                )
                for (anchor in statusRevokeAnchors) {
                    val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                    for (def in defs) {
                        if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                        val t = def.type
                        if (t.startsWith("Landroid") || t.startsWith("Ljava") || t.startsWith("Lkotlin")) continue
                        val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                        for (method in clazz.methods) {
                            if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                            if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                            val impl = method.implementation ?: continue
                            if (impl.instructions.count() > 150) continue
                            val sname = method.name.lowercase()
                            val isStatusRevokeMethod = sname.contains("revoke") ||
                                sname.contains("delete") ||
                                sname.contains("status") ||
                                sname.contains("story") ||
                                sname.contains("process") ||
                                sname.contains("handle") ||
                                sname.contains("deliver")
                            if (!isStatusRevokeMethod) continue
                            try {
                                when (method.returnType) {
                                    "V" -> method.returnEarly()
                                    "Z" -> method.returnEarly(false)
                                }
                            } catch (_: Exception) {}
                        }
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // 6. REMOVE META AI
        // ══════════════════════════════════════════════════════════════════════
        if (removeMetaAI == true) {
            val seen2 = mutableSetOf<String>()

            val aiAnchors = listOf(
                "bonsai_meta_ai_button_setting_enabled",
                "Meta AI", "meta_ai", "MetaAI", "metaai",
                "AiFragmentBase", "aihub", "com.whatsapp.aihub",
                "Ask Meta AI", "meta-ai",
            )

            fun looksLikeShowGate(name: String): Boolean {
                val n = name.lowercase()
                return n.contains("meta") || n.contains("ai") || n.contains("bonsai") ||
                    n.contains("bot") || n.startsWith("is") || n.startsWith("has") ||
                    n.startsWith("should") || n.startsWith("can") || n.startsWith("get") ||
                    n.startsWith("check") || n.length <= 4
            }

            for (anchor in aiAnchors) {
                val defs = try { classDefByStrings(anchor) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                    val typeName = def.type
                    if (typeName.startsWith("Landroid") || typeName.startsWith("Landroidx") ||
                        typeName.startsWith("Ljava") || typeName.startsWith("Lkotlin") ||
                        typeName.startsWith("Lcom/google")
                    ) continue
                    val inScope =
                        typeName.contains("whatsapp", ignoreCase = true) ||
                            typeName.contains("aihub", ignoreCase = true) ||
                            typeName.contains("metaai", ignoreCase = true) ||
                            typeName.startsWith("LX/") ||
                            typeName.startsWith("Lcom/whatsapp")
                    if (!inScope && metaAIAggressive != true) continue
                    if (!seen2.add(typeName)) continue

                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    var local = 0
                    for (method in clazz.methods) {
                        if (AccessFlags.ABSTRACT.isSet(method.accessFlags)) continue
                        if (AccessFlags.NATIVE.isSet(method.accessFlags)) continue
                        val impl = method.implementation ?: continue
                        val n = method.name
                        val count = impl.instructions.count()

                        if (method.returnType == "Z" && method.parameterTypes.isEmpty()) {
                            if (count < 1 || count > 60) continue
                            if (metaAIAggressive != true && !looksLikeShowGate(n)) continue
                            try {
                                method.returnEarly(false)
                                local++
                            } catch (_: Exception) {}
                            if (local >= if (metaAIAggressive == true) 14 else 8) break
                        }

                        if (method.returnType == "V" && method.parameterTypes.size <= 1) {
                            if (count < 1 || count > 40) continue
                            val lower = n.lowercase()
                            if (!lower.contains("meta") && !lower.contains("aihub") &&
                                !lower.contains("bonsai") && !lower.contains("fab")
                            ) continue
                            if (!lower.contains("show") && !lower.contains("bind") &&
                                !lower.contains("setup") && !lower.contains("init") &&
                                !lower.contains("attach") && !lower.contains("update") &&
                                !lower.contains("create")
                            ) continue
                            try { method.returnEarly() } catch (_: Exception) {}
                        }
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════════════════════════
        // 7. USAGE DATA / TELEMETRY
        // ══════════════════════════════════════════════════════════════════════
        if (telemetry == true) {
            val markers = listOf("WamEvent", "FieldStats", "FacebookAnalytics")
            for (marker in markers) {
                val defs = try { classDefByStrings(marker) } catch (_: Exception) { emptyList() }
                for (def in defs) {
                    val clazz = try { mutableClassDefBy(def) } catch (_: Exception) { continue }
                    for (method in clazz.methods) {
                        if (method.returnType != "V") continue
                        if (method.implementation == null) continue
                        val n = method.name
                        if (n != "log" && n != "track" && n != "record" &&
                            n != "logEvent" && !n.startsWith("log")
                        ) continue
                        try { method.returnEarly() } catch (_: Exception) {}
                    }
                }
            }
        }

        // Soft success throughout — missing anchors do not fail the patch session.
    }
}
