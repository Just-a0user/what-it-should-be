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

<!-- Do not modify this section by hand. The patch list is generated when release.yml creates a new release. -->

#### A list of the patches will automatically be shown here after the first patches release is created.

&nbsp;

## 🧑‍💻 Dev usage

- **Make all changes to the `dev` branch.**
- Build locally with `./gradlew buildAndroid`. The bundle is written to `patches/build/libs/patches-*.mpp`.
- Use semantic commit messages: `feat:`, `fix:` or `chore:`. Only `feat:` and `fix:` create a release.
- Do not edit `patches-list.json`, `patches-bundle.json` or `CHANGELOG.md` by hand, `release.yml` updates them.

<!-- PATCHES_END -->

### 🛠️ Building locally

- Run `./gradlew buildAndroid`
- The built patches .mpp file is found in `patches/build/libs/patches-*.mpp`
- Patch the mpp file using [Morphe-Desktop](https://github.com/MorpheApp/morphe-desktop)
  like any other patch bundle.

## 📜 License

These patches are licensed under the [GNU General Public License v3.0](LICENSE).
