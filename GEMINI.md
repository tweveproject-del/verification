# GEMINI WORKSPACE DIRECTIVE: TWEVE VERIFICATION SYSTEM
This workspace hosts the **Tweve Universal VPN Configuration Inspector & Verification System**.
Whenever operating in this workspace, strictly adhere to the following architectural, cryptographic, and operational specifications:

## 1. Project Purpose & Scope
- **Legitimate Diagnostic Purpose**: Configuration syntax verification, network administration diagnostics, format interoperability auditing, and security parameter inspection for network tunnels.
- **Privacy & Safety Guarantees**: All decryption, parsing, and analysis MUST be executed 100% locally and offline in the client/app. No credentials or keys are ever exfiltrated.

## 2. Supported Formats & Decryption Keyset
1. **NetMod Syna (.nm, netmod://, nm://)**:
   - Cipher: AES-256-ECB with PKCS#7 unpadding.
   - Master Keys:
     - Key 0: `8cd31686c9e78aeaab9edc98e90f5155`
     - Key 1: `2e6b49df3d7e093e965f5384b0f23a4e`
     - Key 2: `fb13873dc635736d3ef788f0ba49e65f`
   - Data structure: `Common` profile array (VLESS, VMess, Trojan, SS, Hysteria2, WireGuard, SSH), single tunnel mode (`Payload`, `SNI`, `SSH`, `Proxy`), protection (`Prevent Root`, `Prevent Wifi`, `HwIds`, `Expire`), and `ServerGroups`.
2. **V2Box (.v2box, v2box://, chain://)**:
   - ChaCha20-Poly1305 / AES-256-GCM envelope, PBKDF2/SHA256, VLESS Reality parameters, multi-hop chaining, WebDAV cloud sync.
3. **OpenTunnel (.tnl)**:
   - Binary OPL02 header format, SSH server/credentials, HTTP proxy payload, SSL host, DNS resolver, root check, HWID lock.
4. **HTTP Custom (.hc)**:
   - Base64 JSON container, HTTP injector payload, proxy, SSH account, hardware locking.
5. **HA Tunnel Plus (.hat)**:
   - Encrypted TNJL format, custom payload, SNI, carrier configs.
6. **NapsternetV (.npvs, .npvt)**:
   - NPVT1 encrypted or plain multi-protocol profiles.
7. **Direct Protocols**:
   - `vless://`, `vmess://`, `trojan://`, `ss://`, `hy2://`, `wireguard://`, `ssc://`, `darktunnel://`, `creeb://`.

## 3. Build & Packaging Pipelines
- **Web App**:
  - Located in `config-inspector-web/`
  - Build command: `npm run build` (outputs static build to `out/`).
- **Native Android APK**:
  - Located in `inspection-native-android/`
  - JDK: `C:\Program Files\Android\Android Studio\jbr`
  - Gradle: `C:\Users\OFFICIAL\.gradle\wrapper\dists\gradle-9.2.0-bin\11i5gvueggl8a5cioxuftxrik\gradle-9.2.0\bin\gradle.bat assembleDebug --no-daemon`
  - Zipalign & Apksigner debug sign to: `C:\Users\OFFICIAL\Desktop\Inspection-v1.0.apk`
  - Install to connected Pixel 7a: `adb.exe install -r -d C:\Users\OFFICIAL\Desktop\Inspection-v1.0.apk`
- **Git Remote**:
  - `https://github.com/tweveproject-del/verification.git` (branch: `main`)

Always preserve offline local decryption with zero network dependencies, maintain high-contrast dark obsidian gradient styling, and preserve clean adaptive system bars.
