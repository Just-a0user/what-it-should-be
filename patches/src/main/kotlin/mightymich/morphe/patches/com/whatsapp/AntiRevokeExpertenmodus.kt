package mightymich.morphe.patches.com.whatsapp

import app.morphe.patcher.patch.booleanOption
import app.morphe.patcher.patch.classDefByStrings
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly
import com.android.tools.smali.dexlib2.AccessFlags

/**
 * Anti Revoke Expertenmodus — Prevent others from deleting their messages or statuses.
 *
 * Companion to KeepDeletedMessages (which suppresses the client-side wipe).
 * This patch targets the outgoing revoke-acknowledgement path so the client
 * never confirms receipt of a "delete for everyone" instruction to the server.
 *
 * Strategy:
 *  1. Suppress the ACK/confirmation that tells the server the revoke was applied.
 *  2. No-op status/story revoke delivery handlers.
 *  3. Force the "pending revoke" queue drain to silently drop items.
 *
 * String anchors verified on 2.26.44.90; soft-success on partial hits.
 */
@Suppress("unused")
val antiRevokeExpertenmodusPatch = patch(
    name = "Anti Revoke Expertenmodus",
    description = "Prevent others from deleting their messages or statuses. " +
        "Companion to Keep Deleted Messages — that patch keeps text visible locally; " +
        "this one stops the revoke ACK so the server cannot confirm delivery of the deletion.",
    default = true,
) {
    compatibleWith(WhatsAppCompatibility.WHATSAPP)

    val statuses by booleanOption(
        key = "statuses",
        default = true,
        title = "Block status revokes",
        description = "Also prevent others from deleting their status/story updates.",
    )

    execute {
        var hits = 0

        // ── 1. Outgoing revoke-ACK / confirmation methods ────────────────────
        val ackAnchors = listOf(
            "sendRevokeAck",
            "revokeAck",
            "revoke_ack",
            "RevokeAck",
            "processRevokeAck",
            "handleRevokeConfirm",
            "confirmRevoke",
            "RevokeConfirmProcessor",
            "msgstore/revoke: Failed to re-insert revoked message:",
            "UserActionsMessageDeletion/userActionRevokeMessages",
            "/processMessage revoked message ",
        )

        for (anchor in ackAnchors) {
            val defs = try {
                classDefByStrings(anchor)
            } catch (_: Exception) {
                emptyList()
            }
            for (def in defs) {
                if (AccessFlags.INTERFACE.isSet(def.accessFlags)) continue
                val t = def.type
                if (t.startsWith("Landroid") || t.startsWith("Landroidx") ||
                    t.startsWith("Ljava") || t.startsWith("Lkotlin")
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
                    if (count < 2 || count > 180) continue

                    val name = method.name.lowercase()
                    val isAckMethod = name.contains("ack") ||
                        name.contains("confirm") ||
                        name.contains("revoke") ||
                        name.contains("delete") ||
                        name.contains("process") ||
                        name.contains("send") ||
                        name.contains("handle")

                    if (!isAckMethod) continue

                    try {
                        when (method.returnType) {
                            "V" -> {
                                method.returnEarly()
                                hits++
                            }
                            "Z" -> {
                                method.returnEarly(false)
                                hits++
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }

        // ── 2. Pending revoke queue drain ─────────────────────────────────────
        val queueAnchors = listOf(
            "RevokeQueue",
            "pendingRevoke",
            "pending_revoke",
            "PendingRevokeProcessor",
            "drainRevoke",
            "flushRevoke",
        )

        for (anchor in queueAnchors) {
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
                    if (impl.instructions.count() > 150) continue

                    try {
                        when (method.returnType) {
                            "V" -> {
                                method.returnEarly()
                                hits++
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
            }
        }

        // ── 3. Status / story revoke delivery ────────────────────────────────
        if (statuses == true) {
            val statusRevokeAnchors = listOf(
                "StatusRevoke",
                "status_revoke",
                "StoryRevoke",
                "story_revoke",
                "revokeStatus",
                "deleteStatus",
                "StatusDelete",
                "StatusDeleteProcessor",
            )

            for (anchor in statusRevokeAnchors) {
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
                        if (impl.instructions.count() > 150) continue

                        try {
                            when (method.returnType) {
                                "V" -> {
                                    method.returnEarly()
                                    hits++
                                }
                                "Z" -> {
                                    method.returnEarly(false)
                                    hits++
                                }
                            }
                        } catch (_: Exception) {
                        }
                    }
                }
            }
        }

        // Soft success — zero hits still installs cleanly.
    }
}
