package mightymich.morphe.patches.com.whatsapp

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility

object WhatsAppCompatibility {
    val WHATSAPP = Compatibility(
        name = "WhatsApp",
        packageName = "com.whatsapp",
        apkFileType = ApkFileType.APK,
        appIconColor = 0x25D366,
        targets = listOf(
            AppTarget(
                version = "2.26.45.93",
            ),
        ),
    )
}
