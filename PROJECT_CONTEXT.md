# Universal VPN Configuration Verification & Inspection Engine
## Project Context, Technical Specifications & Handover Reference

---

### 1. Executive Summary & Project Purpose
* **Project Name**: Universal Configuration Inspector & Verification System (Tweve Inspection)
* **Target Platforms**:
  1. **Web Verification Portal**: Next.js 15, TypeScript, Tailwind CSS (`config-inspector-web`)
  2. **Native Android App**: Native Kotlin, Android WebView Bridge, Offline FIPS-197 Engine (`inspection-native-android` / `Inspection-v1.0.apk`)
* **Primary Scope**: Network administration, configuration syntax verification, protocol debugging, security attribute auditing, and cross-client interoperability analysis.
* **Core Philosophy**: 100% offline client-side parsing and decryption with zero third-party telemetry or remote credential exposure.

---

### 2. Architecture & Directory Hierarchy
```
recovery_decoded/
├── config-inspector-web/           # Next.js 15 Web Portal & TypeScript Inspector
│   ├── app/
│   │   ├── inspector-engine.ts     # Pure TS cryptographic & format parsing engine
│   │   ├── page.tsx               # Reactive inspector UI & protocol cards
│   │   └── globals.css            # Dark Obsidian theme & vibrant protocol gradients
│   ├── scripts/
│   │   └── build-static.mjs       # Static export builder & asset packager
│   └── out/                       # Pre-rendered static distribution
├── inspection-native-android/     # Kotlin Android Application
│   ├── app/src/main/
│   │   ├── AndroidManifest.xml    # Intent filters for all VPN extensions & schemes
│   │   ├── assets/www/            # Bundled offline web engine
│   │   └── java/com/tweve/inspection/
│   │       ├── ui/MainActivity.kt # WebView bridge, system insets & file intents
│   │       ├── engine/InspectorEngine.kt # Native Kotlin fallback parser
│   │       └── model/InspectionModels.kt # Typed configuration models
└── PROJECT_CONTEXT.md             # This persistent specification reference
```

---

### 3. Supported VPN Formats & Cryptographic Specifications

#### A. NetMod Syna (`.nm`, `netmod://`, `nm://`)
* **Application**: NetMod Syna by Eichgee (`com.netmod.syna`)
* **Cipher**: AES-256-ECB with PKCS#7 / PKCS#5 unpadding on Base64-decoded body.
* **Core JNI Keyset (libgojni.so)**:
  1. Keyset 0: `8cd31686c9e78aeaab9edc98e90f5155`
  2. Keyset 1: `2e6b49df3d7e093e965f5384b0f23a4e`
  3. Keyset 2: `fb13873dc635736d3ef788f0ba49e65f`
* **Schema Capabilities**:
  * Multi-Profile Array (`Common`): VLESS, VMess, Trojan, Shadowsocks, Hysteria2, WireGuard, SSH, Direct HTTP.
  * Security Matrix: `Prevent Root` (Device root detection), `Prevent Wifi` (Cellular-only lock), `HwIds` (Hardware binding), `Expire` (Expiration timestamp).
  * Direct Tunnel Mode: `Payload` (HTTP Custom injection syntax), `SNI`, `Proxy`, `SSH`, `Interface`, `Peer`.
  * Cloud Server Groups: `ServerGroups` array with subscription URLs.

#### B. V2Box Client (`.v2box`, `v2box://`, `chain://`)
* **Package**: `com.v2ray.box`
* **Cipher**: ChaCha20-Poly1305 / AES-256-GCM envelope with PBKDF2/SHA256 key derivation.
* **Capabilities**: VLESS Reality (PubKey, ShortID, SpiderX), VMess, Trojan, Shadowsocks, Hysteria 2, WireGuard, WebDAV Cloud Sync, and Multi-Hop Chaining.

#### C. OpenTunnel (`.tnl`)
* **Package**: `com.rcreations.opentunnel`
* **Envelope**: Binary format with `OPL02` magic header.
* **Capabilities**: SSH server/credentials, HTTP proxy payload, SSL host, DNS resolver, root check, HWID lock, and embedded V2Ray JSON.

#### D. HTTP Custom (`.hc`)
* **Package**: `com.shagbag.httpcustom`
* **Format**: Base64 JSON container with mode flags, payload, remote proxy, SSH credentials, and hardware binding.

#### E. HA Tunnel Plus (`.hat`)
* **Package**: `com.hatunnel.plus`
* **Format**: Encrypted TNJL envelope containing server endpoint, carrier profile, custom payload, SNI, and device protection flags.

#### F. NapsternetV (`.npvs`, `.npvt`)
* **Format**: NPVT1 encrypted or plain multi-protocol profiles (V2Ray, Xray, Psiphon, SSH).

#### G. Direct Protocols & Schemes
* `vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `wireguard://`, `ssc://`, `darktunnel://`, `creeb://`.

---

### 4. Build, Compilation & Deployment Reference

#### Web Portal Static Build
```bash
cd config-inspector-web
npm run build
# Output is placed in config-inspector-web/out/
```

#### Android Native Compilation & Signing
```powershell
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
$env:PATH = "$env:JAVA_HOME\bin;C:\Users\OFFICIAL\AppData\Local\Android\Sdk\build-tools\36.0.0;C:\Users\OFFICIAL\AppData\Local\Android\Sdk\platform-tools;$env:PATH"
Set-Location "c:\Users\OFFICIAL\Music\recovery_decoded\inspection-native-android"

# Sync assets
Copy-Item -Path "..\config-inspector-web\out\*" -Destination "app\src\main\assets\www\" -Recurse -Force

# Build debug APK
& "C:\Users\OFFICIAL\.gradle\wrapper\dists\gradle-9.2.0-bin\11i5gvueggl8a5cioxuftxrik\gradle-9.2.0\bin\gradle.bat" assembleDebug --no-daemon

# Zipalign & Sign
$unaligned = "app\build\outputs\apk\debug\app-debug.apk"
$aligned = "app\build\outputs\apk\debug\app-aligned.apk"
$target = "C:\Users\OFFICIAL\Desktop\Inspection-v1.0.apk"

zipalign.exe -p -f 4 $unaligned $aligned
apksigner.bat sign --ks "$env:USERPROFILE\.android\debug.keystore" --ks-pass pass:android --key-pass pass:android --out $target $aligned

# Install to connected device
adb.exe install -r -d $target
```

---

### 5. Repository & Version Control
* **Git Remote**: `https://github.com/tweveproject-del/verification.git`
* **Branch**: `main`
* **Primary Maintainer**: Tweve Project

---

### 6. Assistant Prompt Instruction (Copy-Paste for Future Chats)
When starting a new session or switching environments, provide this prompt:
> *"I am working on the Tweve Universal Configuration Verification & Inspection system located in `c:\Users\OFFICIAL\Music\recovery_decoded`. Please refer to `PROJECT_CONTEXT.md` in the project root for full architectural details, supported VPN client schemas (NetMod Syna, V2Box, OpenTunnel, HC, HA Tunnel, NapsternetV), cryptographic specifications, build pipelines, and offline verification goals. Please continue development and support based on these documented specifications."*
