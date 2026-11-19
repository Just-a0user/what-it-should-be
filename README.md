# WhatsApp Patches

Patches for [WhatsApp](https://www.whatsapp.com/) (`com.whatsapp`) for use with [Morphe](https://github.com/MorpheApp/morphe-documentation).

Target version: **2.26.44.90**

## ❓ About

| Patch | What it does |
|---|---|
| View once media | Lets you reopen and save view once photos and videos. |
| Keep deleted messages | Keeps messages that were deleted for everyone visible locally. |
| Remove Meta AI | Hides Meta AI entry points on the chats screen. |
| Usage data | Limits diagnostic and analytics data WhatsApp sends. |

The patches find their targets through strings that survive obfuscation, not through fixed class names. If an
anchor is missing in a WhatsApp version, the patch applies without effect instead of failing.

### How to use these patches

Click the button below, or manually add this repo url to Morphe Manager: https://github.com/Just-a0user/what-it-should-be

<a href="https://morphe.software/add-source?github=Just-a0user/what-it-should-be">
  <img src=".github/assets/add-to-morphe.svg" alt="Add to Morphe" height="48">
</a>

## 🩹 Patches list

<!-- PATCHES_START EXPANDED -->
> **[v1.1.1](https://github.com/Just-a0user/what-it-should-be/releases/tag/v1.1.1)**&nbsp;&nbsp;•&nbsp;&nbsp;`main`&nbsp;&nbsp;•&nbsp;&nbsp;7 patches total
<details open>
<summary>📦 WhatsApp&nbsp;&nbsp;•&nbsp;&nbsp;7 patches</summary>
<br>

**Package name:** `com.whatsapp`

**🎯 Supported versions:**

| 2.26.45.93 |
| :---: |

| 💊&nbsp;Patch | 📜&nbsp;Description | ⚙️&nbsp;Options |
|----------|----------------|-----------|
| [Anti Detector](#anti-detector) | Spoof APK-integrity, root, Xposed, and Play Integrity checks so WhatsApp reports a clean, unmodified install to its own telemetry and to its server. | • Spoof root detection<br>• Spoof Xposed / LSPosed detection<br>• Spoof Play Integrity / SafetyNet |
| [Anti Revoke Expertenmodus](#anti-revoke-expertenmodus) | Prevent others from deleting their messages or statuses. Companion to Keep Deleted Messages — that patch keeps text visible locally; this one stops the revoke ACK so the server cannot confirm delivery of the deletion. | • Block status revokes |
| [Keep deleted messages](#keep-deleted-messages) | Show messages that were deleted for everyone. Client-side only; already-wiped history cannot be restored. | • Highlight deleted messages |
| [Login Fix Expertenmodus](#login-fix-expertenmodus) | Experimental login compatibility patch for a re-signed APK. Requires compatible microG-RE components. Enable only if registration/login fails. |  |
| [Remove Meta AI](#remove-meta-ai) | Hides Meta AI on the chats home screen (FAB / pill), related hub entry points, and common feature gates. Does not delete existing Meta AI chats. | • Aggressive hide |
| [Usage data](#usage-data) | Limit diagnostic and analytics data WhatsApp sends. |  |
| [View once media](#view-once-media) | Allow reopening and saving view once photos and videos. |  |

</details>

<!-- PATCHES_END -->

### 🛠️ Building locally

- Run `./gradlew buildAndroid`
- The built patches .mpp file is found in `patches/build/libs/patches-*.mpp`
- Patch the mpp file using [Morphe-Desktop](https://github.com/MorpheApp/morphe-desktop)
  like any other patch bundle.

## 📜 License

These patches are licensed under the [GNU General Public License v3.0](LICENSE).
