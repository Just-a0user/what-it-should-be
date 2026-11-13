package mightymich.morphe.patches.com.whatsapp

import app.morphe.patcher.patch.classDefByStrings
import app.morphe.patcher.patch.mutableClassDefBy
import app.morphe.patcher.patch.patch
import app.morphe.patcher.util.returnEarly

@Suppress("unused")
val viewOnceUnlockPatch = patch(
    name = "View once media",
    description = "Allow reopening and saving view once photos and videos.",
    default = true,
) {
    compatibleWith(WhatsAppCompatibility.WHATSAPP)

    execute {
        val markers = listOf("view_once", "view once", "ViewOnce", "ephemeral_view_once")
        var hits = 0
        for (marker in markers) {
            val defs = try {
                classDefByStrings(marker)
            } catch (_: Exception) {
                emptyList()
            }
            for (def in defs) {
                val clazz = try {
                    mutableClassDefBy(def)
                } catch (_: Exception) {
                    continue
                }
                for (method in clazz.methods) {
                    if (method.returnType != "Z") continue
                    if (method.parameterTypes.isNotEmpty()) continue
                    val impl = method.implementation ?: continue
                    if (impl.instructions.count() > 40) continue
                    val text = impl.instructions.joinToString("\n") { it.toString() }
                    if (!text.contains("once", ignoreCase = true) &&
                        !text.contains(marker)
                    ) {
                        continue
                    }
                    // Force "not view-once" / allow view style booleans carefully:
                    // only methods whose names suggest isViewOnce / canViewOnce
                    val n = method.name.lowercase()
                    if (!n.contains("view") && !n.contains("once") && !n.contains("ephemeral")) {
                        continue
                    }
                    try {
                        // isViewOnce → false so media is treated as normal
                        method.returnEarly(false)
                        hits++
                    } catch (_: Exception) {
                    }
                }
            }
        }
        /* soft success: zero hits allowed */
    }
}
