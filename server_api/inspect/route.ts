import { NextRequest, NextResponse } from 'next/server';
import crypto from 'crypto';
import net from 'net';
import tls from 'tls';
import dgram from 'dgram';
import dns from 'dns/promises';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

const CLOUD_API_BASE = 'https://tunneltweak.com/api/cloudconfig';
const AES_KEY = 'TunnelTweak2024!';
const SECURE_SECRET = 'TunnelTweak-Secure-v1';
const PASSPHRASE_PREFIX = 'TTPBE1:';

const CONNECTION_TYPES: Record<number, {
  name: string;
  category: 'SSH' | 'Proxy' | 'DNSTT' | 'V2Ray' | 'Hysteria2' | 'WireGuard' | 'Slipstream';
  badgeColor: string;
  description: string;
  flowDiagram: string[];
}> = {
  0: {
    name: 'SSH Direct',
    category: 'SSH',
    badgeColor: 'cyan',
    description: 'Direct TCP connection to SSH Server on SSH Port without proxy or TLS wrapping.',
    flowDiagram: ['Client App', 'TCP Direct', 'SSH Server (:22)'],
  },
  1: {
    name: 'SSH + Payload',
    category: 'SSH',
    badgeColor: 'cyan',
    description: 'Injects custom HTTP Payload header directly into the SSH Server port (or HTTP port) before SSH handshake.',
    flowDiagram: ['Client App', 'HTTP Payload Injection', 'SSH Server'],
  },
  2: {
    name: 'SSH + SSL (TLS/SNI)',
    category: 'SSH',
    badgeColor: 'indigo',
    description: 'Wraps the SSH connection inside a TLS/SSL tunnel using a spoofed SNI (Bug Host) to bypass DPI.',
    flowDiagram: ['Client App', 'TLS Handshake (SNI)', 'SSL Port (:443)', 'SSH Server'],
  },
  3: {
    name: 'SSH + SSL + Payload',
    category: 'SSH',
    badgeColor: 'indigo',
    description: 'Establishes a TLS/SNI connection first, then injects the custom HTTP Payload inside the encrypted TLS stream before starting SSH.',
    flowDiagram: ['Client App', 'TLS (SNI)', 'HTTP Payload', 'CDN / SSL Server', 'SSH Server'],
  },
  4: {
    name: 'HTTP Proxy',
    category: 'Proxy',
    badgeColor: 'blue',
    description: 'Connects through an intermediate HTTP CONNECT Proxy to reach the SSH Server.',
    flowDiagram: ['Client App', 'HTTP CONNECT', 'Remote Proxy', 'SSH Server'],
  },
  5: {
    name: 'HTTP Proxy + Payload',
    category: 'Proxy',
    badgeColor: 'blue',
    description: 'Sends a custom HTTP Payload (e.g. WebSocket Upgrade / Split / Front-Query) to the Proxy Host:Port to reach the SSH Server.',
    flowDiagram: ['Client App', 'Custom HTTP Payload', 'Proxy / CDN (:80/:8080)', 'SSH Server'],
  },
  6: {
    name: 'SlowDNS (DNSTT)',
    category: 'DNSTT',
    badgeColor: 'purple',
    description: 'Encapsulates SSH traffic inside DNS queries (TXT/NULL/CNAME) via a DNS Resolver to an authoritative DNSTT Nameserver.',
    flowDiagram: ['Client App', 'UDP/53 DNS Queries', 'DNS Resolver', 'DNSTT Nameserver (PubKey)', 'Local Loopback', 'SSH Server'],
  },
  7: {
    name: 'HTTP Proxy + SSL + Payload',
    category: 'Proxy',
    badgeColor: 'indigo',
    description: 'Connects to Proxy Host:Port over TLS (with custom SNI), then sends the HTTP Payload to establish an SSH tunnel.',
    flowDiagram: ['Client App', 'TLS (SNI)', 'HTTP Payload', 'Proxy / CDN (:443)', 'SSH Server'],
  },
  8: {
    name: 'DNSTT + V2Ray',
    category: 'V2Ray',
    badgeColor: 'emerald',
    description: 'Hybrid tunnel: establishes a SlowDNS (DNSTT) transport layer and routes V2Ray (VLESS/VMess/Trojan) protocol frames inside it.',
    flowDiagram: ['Client App', 'Xray Core (V2Ray)', 'DNSTT Client', 'DNS Resolver', 'DNSTT Nameserver', 'V2Ray Server'],
  },
  9: {
    name: 'V2Ray (Xray Core)',
    category: 'V2Ray',
    badgeColor: 'emerald',
    description: 'Full Xray/V2Ray outbound tunnel supporting VLESS, VMess, and Trojan over TCP, WebSocket (CDN), or gRPC with TLS or REALITY.',
    flowDiagram: ['Client App', 'Xray Core (VLESS/VMess/Trojan)', 'Transport (TCP/WS/gRPC)', 'Security (TLS/REALITY)', 'V2Ray Server'],
  },
  10: {
    name: 'DNSTT + SOCKS',
    category: 'DNSTT',
    badgeColor: 'purple',
    description: 'Establishes a SlowDNS (DNSTT) tunnel directly into a remote SOCKS5 endpoint without SSH overhead.',
    flowDiagram: ['Client App', 'SOCKS5', 'DNSTT Client', 'DNS Resolver', 'DNSTT Nameserver'],
  },
  11: {
    name: 'Hysteria2 (QUIC)',
    category: 'Hysteria2',
    badgeColor: 'amber',
    description: 'High-speed UDP/QUIC protocol with Brutal congestion control, Salamander obfuscation, and dynamic UDP port hopping.',
    flowDiagram: ['Client App', 'QUIC / UDP (Salamander Obfs)', 'Port Hopping', 'Hysteria2 Server'],
  },
  12: {
    name: 'WireGuard',
    category: 'WireGuard',
    badgeColor: 'rose',
    description: 'Modern Layer-3 cryptographic UDP VPN tunnel using Curve25519, ChaCha20-Poly1305, and BLAKE2s.',
    flowDiagram: ['Client App (tun0)', 'UDP Noise_IK Handshake', 'WireGuard Peer Endpoint'],
  },
  13: {
    name: 'Slipstream',
    category: 'Slipstream',
    badgeColor: 'teal',
    description: 'High-efficiency segmented DNS/direct tunnel with Slipstream certificate authentication.',
    flowDiagram: ['Client App', 'Slipstream Segmented Stream', 'Slipstream Domain / Server'],
  },
  14: {
    name: 'SSH Custom (Ssc://) Sealed Cloud Profile',
    category: 'SSH',
    badgeColor: 'amber',
    description: 'AEAD-sealed SSH Custom (Ssc://) binary profile containing hardware-locked tunnel parameters (SSH/SlowDNS/V2Ray/Payload).',
    flowDiagram: ['SSH Custom App', 'Ssc:// AEAD Container', 'Native libssc.so Decryption', 'Tunnel Endpoint'],
  },
  15: {
    name: 'Creeb Injector Cloud Profile (CREEBINJ)',
    category: 'SSH',
    badgeColor: 'emerald',
    description: 'Creeb Injector (CREEBINJ-<ID>) cloud reference token supporting SSH, SSL/TLS, HTTP Proxy, SlowDNS (DNSTT), UDP (Hysteria), and V2Ray.',
    flowDiagram: ['Creeb Injector App', 'CREEBINJ Cloud ID Lookup', 'Server / SNI / DNSTT / V2Ray Tunnel'],
  },
};

function withTimeout<T>(promise: Promise<T>, ms: number, fallbackValue: T): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((resolve) => setTimeout(() => resolve(fallbackValue), ms)),
  ]);
}

function decryptAES(encryptedBase64: string): string | null {
  try {
    const clean = encryptedBase64.trim();
    const raw = Buffer.from(clean, 'base64');
    if (raw.length <= 16) return null;
    const iv = raw.subarray(0, 16);
    const cipherText = raw.subarray(16);
    const key = Buffer.from(AES_KEY, 'utf8');
    const decipher = crypto.createDecipheriv('aes-128-cbc', key, iv);
    const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

function decryptSecureConfig(encryptedBase64: string): string | null {
  try {
    const clean = encryptedBase64.trim();
    const raw = Buffer.from(clean, 'base64');
    if (raw.length < 44) return null;
    const salt = raw.subarray(0, 16);
    const iv = raw.subarray(16, 28);
    const body = raw.subarray(28);
    const tag = body.subarray(body.length - 16);
    const cipherText = body.subarray(0, body.length - 16);
    const key = crypto.pbkdf2Sync(SECURE_SECRET, salt, 10000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

function decryptWithPassphrase(encryptedPayload: string, passphrase: string): string | null {
  try {
    let clean = encryptedPayload.trim();
    if (clean.startsWith(PASSPHRASE_PREFIX)) {
      clean = clean.slice(PASSPHRASE_PREFIX.length).trim();
    }
    const raw = Buffer.from(clean, 'base64');
    if (raw.length < 44) return null;
    const salt = raw.subarray(0, 16);
    const iv = raw.subarray(16, 28);
    const body = raw.subarray(28);
    const tag = body.subarray(body.length - 16);
    const cipherText = body.subarray(0, body.length - 16);
    const key = crypto.pbkdf2Sync(passphrase, salt, 120000, 32, 'sha256');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const decrypted = Buffer.concat([decipher.update(cipherText), decipher.final()]);
    return decrypted.toString('utf8');
  } catch {
    return null;
  }
}

function decryptLegacyXOR(encryptedBase64: string): string | null {
  try {
    const raw = Buffer.from(encryptedBase64.trim(), 'base64');
    const out = Buffer.alloc(raw.length);
    for (let i = 0; i < raw.length; i++) {
      out[i] = raw[i] ^ 0x5a;
    }
    const str = out.toString('utf8');
    JSON.parse(str);
    return str;
  } catch {
    return null;
  }
}

/**
 * Parses direct share URIs (vless://, vmess://, trojan://, hy2://, hysteria2://, ss://, or WireGuard INI)
 * into a normalized Tweve Tunnel config JSON object so the inspector can verify them directly!
 */
function tryParseDirectProtocolInput(raw: string): { parsed: Record<string, any>; methodLabel: string } | null {
  const trimmed = raw.trim();

  // 1. VLESS or Trojan URI: vless://uuid@host:port?params#remark
  if (/^(vless|trojan):\/\//i.test(trimmed)) {
    try {
      const url = new URL(trimmed);
      const protocol = url.protocol.replace(':', '').toLowerCase();
      const uuid = decodeURIComponent(url.username);
      const host = url.hostname;
      const port = url.port || '443';
      const params = url.searchParams;
      const remark = decodeURIComponent(url.hash.replace(/^#/, '')) || `${protocol.toUpperCase()} Direct Link`;
      const security = params.get('security') || (protocol === 'trojan' ? 'tls' : 'none');
      const network = params.get('type') || params.get('network') || 'tcp';
      const sni = params.get('sni') || params.get('peer') || '';
      const wsHost = params.get('host') || '';
      const wsPath = params.get('path') || params.get('serviceName') || '/';
      const publicKey = params.get('pbk') || '';
      const shortId = params.get('sid') || '';
      const flow = params.get('flow') || '';
      const fp = params.get('fp') || '';
      const alpn = params.get('alpn') || '';

      return {
        methodLabel: `Direct ${protocol.toUpperCase()} Share URI`,
        parsed: {
          config_version: 7,
          config_message: remark,
          config_protected: false,
          tunnelType: 9,
          type: '9',
          v2ray_protocol: protocol,
          v2ray_server_host: host,
          v2ray_server_port: port,
          v2ray_uuid: uuid,
          v2ray_security: security,
          v2ray_network: network,
          v2ray_sni: sni,
          v2ray_ws_host: wsHost,
          v2ray_ws_path: wsPath,
          v2ray_public_key: publicKey,
          v2ray_short_id: shortId,
          v2ray_flow: flow,
          v2ray_fingerprint: fp,
          v2ray_alpn: alpn,
          v2ray_allow_insecure: params.get('allowInsecure') === '1' || params.get('insecure') === '1',
          dns1: '8.8.8.8',
          dns2: '8.8.4.4',
        },
      };
    } catch {
      return null;
    }
  }

  // 2. VMess URI: vmess://<base64_json>
  if (/^vmess:\/\//i.test(trimmed)) {
    try {
      const b64 = trimmed.slice('vmess://'.length).trim();
      const jsonStr = Buffer.from(b64, 'base64').toString('utf8');
      const vm = JSON.parse(jsonStr);
      return {
        methodLabel: 'Direct VMess (Base64 JSON) Share URI',
        parsed: {
          config_version: 7,
          config_message: vm.ps || 'VMess Direct Link',
          config_protected: false,
          tunnelType: 9,
          type: '9',
          v2ray_protocol: 'vmess',
          v2ray_server_host: vm.add || '',
          v2ray_server_port: String(vm.port || '443'),
          v2ray_uuid: vm.id || '',
          v2ray_alter_id: String(vm.aid ?? '0'),
          v2ray_security: vm.tls === 'tls' || vm.tls === 'true' ? 'tls' : (vm.security && vm.security !== 'auto' ? vm.security : 'none'),
          v2ray_cipher: vm.scy || 'auto',
          v2ray_network: vm.net || 'tcp',
          v2ray_sni: vm.sni || vm.host || '',
          v2ray_ws_host: vm.host || '',
          v2ray_ws_path: vm.path || '/',
          v2ray_alpn: vm.alpn || '',
          v2ray_fingerprint: vm.fp || '',
          dns1: '8.8.8.8',
          dns2: '8.8.4.4',
        },
      };
    } catch {
      return null;
    }
  }

  // 3. Hysteria2 URI: hy2://auth@host:port?params#remark or hysteria2://
  if (/^(hy2|hysteria2):\/\//i.test(trimmed)) {
    try {
      const normalized = trimmed.replace(/^hysteria2:\/\//i, 'http://').replace(/^hy2:\/\//i, 'http://');
      const url = new URL(normalized);
      const auth = decodeURIComponent(
        url.password ? `${url.username}:${url.password}` : url.username
      );
      const params = url.searchParams;
      const remark = decodeURIComponent(url.hash.replace(/^#/, '')) || 'Hysteria2 Direct Link';
      const obfsType = params.get('obfs') || '';
      const obfsPassword = params.get('obfs-password') || '';
      return {
        methodLabel: 'Direct Hysteria2 Share URI',
        parsed: {
          config_version: 7,
          config_message: remark,
          config_protected: false,
          tunnelType: 11,
          type: '11',
          hysteria_server: url.hostname,
          hysteria_port: url.port || '443',
          hysteria_auth: auth,
          hysteria_sni: params.get('sni') || url.hostname,
          hysteria_insecure: params.get('insecure') === '1' || params.get('insecure') === 'true',
          hysteria_obfs: obfsPassword || obfsType,
          hysteria_ports: params.get('mport') || '',
          hysteria_up: params.get('upmbps') || '50',
          hysteria_down: params.get('downmbps') || '100',
        },
      };
    } catch {
      return null;
    }
  }

  // 4. WireGuard INI Config ([Interface] ... [Peer])
  if (trimmed.includes('[Interface]') && trimmed.includes('[Peer]')) {
    return {
      methodLabel: 'Direct WireGuard INI Configuration',
      parsed: {
        config_version: 7,
        config_message: 'WireGuard Direct Configuration',
        config_protected: false,
        tunnelType: 12,
        type: '12',
        wireguard_config: trimmed,
      },
    };
  }

  return null;
}

/**
 * Pure-JS DJB ChaCha20Legacy (32-byte key, 8-byte nonce, 64-bit block counter starting at 1)
 * Used by SSH Custom (.ssc & Ssc://) 3-layer AEAD encryption.
 */
function rotl32(v: number, c: number): number {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function chachaQuarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
}

function chacha20LegacyBlock(key32: Buffer, nonce8: Buffer, counterLow: number, counterHigh = 0): Buffer {
  const state = new Uint32Array(16);
  // "expand 32-byte k"
  state[0] = 0x61707865;
  state[1] = 0x3320646e;
  state[2] = 0x79622d32;
  state[3] = 0x6b206574;
  for (let i = 0; i < 8; i++) {
    state[4 + i] = key32.readUInt32LE(i * 4);
  }
  state[12] = counterLow >>> 0;
  state[13] = counterHigh >>> 0;
  state[14] = nonce8.readUInt32LE(0);
  state[15] = nonce8.readUInt32LE(4);

  const working = new Uint32Array(state);
  for (let i = 0; i < 10; i++) {
    chachaQuarterRound(working, 0, 4, 8, 12);
    chachaQuarterRound(working, 1, 5, 9, 13);
    chachaQuarterRound(working, 2, 6, 10, 14);
    chachaQuarterRound(working, 3, 7, 11, 15);
    chachaQuarterRound(working, 0, 5, 10, 15);
    chachaQuarterRound(working, 1, 6, 11, 12);
    chachaQuarterRound(working, 2, 7, 8, 13);
    chachaQuarterRound(working, 3, 4, 9, 14);
  }

  const out = Buffer.alloc(64);
  for (let i = 0; i < 16; i++) {
    out.writeUInt32LE((working[i] + state[i]) >>> 0, i * 4);
  }
  return out;
}

function chacha20LegacyDecrypt(ciphertext: Buffer, key32: Buffer, nonce8: Buffer, startCounter = 1): Buffer {
  const out = Buffer.alloc(ciphertext.length);
  let counter = startCounter;
  for (let offset = 0; offset < ciphertext.length; offset += 64) {
    const block = chacha20LegacyBlock(key32, nonce8, counter++);
    const chunkLen = Math.min(64, ciphertext.length - offset);
    for (let i = 0; i < chunkLen; i++) {
      out[offset + i] = ciphertext[offset + i] ^ block[i];
    }
  }
  return out;
}

const SSC_FIXED_NONCE = Buffer.from('74d0f3879f9d47f7', 'hex');
const SSC_L1_KEY = Buffer.from('c8a6a8ea102d5a0baf8fdb1b39cd615c0d07c1edcbde4e82cfdd309bc4587f6b', 'hex');
const SSC_L2_KEY = Buffer.from('7f9db48ffde449ad19f9ed44b8b27eee334ab4a85b972dca8ff20e4e8ed44e4e', 'hex');
const SSC_L3_KEY = Buffer.from('d39394517a48971f6e8555e994bee5bd835e5ab2f85fbd76bbd99800f32b967e', 'hex');

/**
 * Full 3-Stage SSH Custom (Ssc:// & .ssc) Decryptor:
 * - Stage 1: Reverses Ssc:// hex string and decrypts Outer ChaCha20Legacy-Poly1305 AEAD container (L1_KEY + FIXED_NONCE)
 * - Stage 2: Decrypts optional Nested Lock AEAD container (L2_KEY + 8-byte nonce from `a[0..16]`)
 * - Stage 3: Derives per-profile 8-byte nonce from `profile.b` and decrypts all Layer 3 fields
 *   (`g` PAYLOAD, `h` PROXY, `i` PROXY_PORT, `l` SNI_OR_HOST, `o` USERNAME, `p` PASSWORD, `v` DNS, `w` NS_SERVER, `x` PUBKEY),
 *   stripping each field's 16-byte Poly1305 authentication tag.
 */
function tryDecryptSscPayload(raw: string, _customSecret?: string): {
  decryptedJson: Record<string, any> | null;
  encryptionMethod: string;
  error?: string;
} | null {
  const trimmed = raw.trim();
  const hasSscScheme = /^ssc:\/\//i.test(trimmed);
  const compactHex = (hasSscScheme ? trimmed.replace(/^ssc:\/\//i, '') : trimmed).replace(/\s+/g, '');

  // Check if input is Ssc:// URI or raw .ssc hex file
  if (!hasSscScheme && (!/^[0-9a-fA-F]+$/.test(compactHex) || compactHex.length < 64 || compactHex.length % 2 !== 0)) {
    return null;
  }

  if (!/^[0-9a-fA-F]+$/.test(compactHex) || compactHex.length < 36 || compactHex.length % 2 !== 0) {
    return {
      decryptedJson: null,
      encryptionMethod: 'Ssc:// Hex URI (Malformed)',
      error: `Invalid Ssc:// hex payload (${compactHex.length} hex characters). Ensure the full Ssc:// URI was copied without truncation.`,
    };
  }

  // Try reversed hex first (standard for Ssc:// scheme), then unreversed hex (standard for raw .ssc files)
  const candidates = hasSscScheme
    ? [compactHex.split('').reverse().join(''), compactHex]
    : [compactHex, compactHex.split('').reverse().join('')];

  for (const hexCandidate of candidates) {
    try {
      const outerBytes = Buffer.from(hexCandidate, 'hex');
      if (outerBytes.length <= 16) continue;
      const outerCipher = outerBytes.subarray(0, outerBytes.length - 16);
      const outerPlainBuf = chacha20LegacyDecrypt(outerCipher, SSC_L1_KEY, SSC_FIXED_NONCE, 1);
      const outerText = outerPlainBuf.toString('utf8');
      const outerObj = JSON.parse(outerText);
      if (!outerObj || typeof outerObj !== 'object') continue;

      let targetObj: Record<string, any> = outerObj;
      let usedNestedLayer = false;

      // Stage 2: Optional Nested Lock (when `a` is a hex nonce string and `c` is nested ciphertext hex)
      if (
        typeof outerObj.a === 'string' &&
        outerObj.a.length >= 16 &&
        typeof outerObj.c === 'string' &&
        /^[0-9a-fA-F]+$/.test(outerObj.c)
      ) {
        try {
          const nestedNonce = Buffer.from(outerObj.a.slice(0, 16), 'hex');
          const nestedBytes = Buffer.from(outerObj.c, 'hex');
          if (nestedBytes.length > 16) {
            const nestedCipher = nestedBytes.subarray(0, nestedBytes.length - 16);
            const nestedPlain = chacha20LegacyDecrypt(nestedCipher, SSC_L2_KEY, nestedNonce, 1);
            const nestedParsed = JSON.parse(nestedPlain.toString('utf8'));
            if (nestedParsed && typeof nestedParsed === 'object') {
              targetObj = nestedParsed;
              usedNestedLayer = true;
            }
          }
        } catch {
          // Fallback to outerObj if nested layer fails
        }
      }

      // Stage 3: Per-profile Layer 3 field decryption
      const encryptedFields = ['g', 'h', 'i', 'l', 'o', 'p', 'v', 'w', 'x'] as const;
      const remappedProfiles: Array<Record<string, any>> = [];

      if (Array.isArray(targetObj.a)) {
        for (const profile of targetObj.a) {
          if (!profile || typeof profile !== 'object') continue;
          const userKey = typeof profile.b === 'string' ? profile.b.trim() : '';
          let profileNonce: Buffer | null = null;

          if (userKey.length === 32 && /^[0-9a-fA-F]{32}$/.test(userKey)) {
            const suffixReversed = userKey.slice(16, 32).split('').reverse().join('');
            profileNonce = Buffer.from(suffixReversed, 'hex');
          }

          const decodedFields: Record<string, string> = {};
          for (const fieldKey of encryptedFields) {
            const rawVal = profile[fieldKey];
            if (
              profileNonce &&
              typeof rawVal === 'string' &&
              rawVal.length >= 32 &&
              rawVal.length % 2 === 0 &&
              /^[0-9a-fA-F]+$/.test(rawVal)
            ) {
              const ctBytes = Buffer.from(rawVal, 'hex');
              // Every Layer 3 field in SSH Custom ends with a 16-byte Poly1305 tag
              const cipherSlice = ctBytes.subarray(0, Math.max(0, ctBytes.length - 16));
              if (cipherSlice.length === 0) {
                decodedFields[fieldKey] = '';
              } else {
                const ptBuf = chacha20LegacyDecrypt(cipherSlice, SSC_L3_KEY, profileNonce, 1);
                const zeroIdx = ptBuf.indexOf(0);
                const cleanBuf = zeroIdx >= 0 ? ptBuf.subarray(0, zeroIdx) : ptBuf;
                decodedFields[fieldKey] = cleanBuf.toString('utf8');
              }
            } else if (typeof rawVal === 'string') {
              decodedFields[fieldKey] = rawVal;
            } else {
              decodedFields[fieldKey] = '';
            }
          }

          remappedProfiles.push({
            PROFILE_ID: profile.a,
            USER_KEY_NONCE_SEED: userKey,
            CONFIG_NAME: profile.e || 'SSH Custom Profile',
            TUNNEL_TYPE: profile.j || 'TLS',
            PROTOCOL_ID: profile.r ?? 0,
            VERSION: profile.s ?? targetObj.d ?? 96,
            SNI_OR_HOST: decodedFields.l || '',
            PORT: profile.m ?? 22,
            SSH_PORT: profile.z ?? 2222,
            USERNAME: decodedFields.o || '',
            PASSWORD: decodedFields.p || '',
            UDPGW_PORT: profile.q ?? 7300,
            DNS_RESOLVER: decodedFields.v || '',
            NS_SERVER: decodedFields.w || '',
            PUBKEY: decodedFields.x || '',
            PAYLOAD_ENABLED: Boolean(profile.f),
            PAYLOAD: decodedFields.g || '',
            PROXY_ENABLED: Boolean(profile.k),
            PROXY: decodedFields.h || '',
            PROXY_PORT: decodedFields.i || '',
            IS_PREMIUM: Boolean(profile.n),
            IS_DEFAULT: Boolean(profile.y),
            ENCRYPTION: profile.t ?? 0,
            COMPRESSION: profile.u ?? 0,
            HWID_LOCK: Boolean(profile.ab),
            ROOT_LOCK: Boolean(profile.ac),
            PLAYSTORE_LOCK: Boolean(profile.ad),
            EXPIRY_LOCK: Boolean(profile.ae),
            PASSWORD_LOCK: Boolean(profile.ag),
          });
        }
      }

      const primary = remappedProfiles[0] || {};
      const outerTitle = typeof targetObj.f === 'string' ? targetObj.f.trim() : typeof outerObj.f === 'string' ? outerObj.f.trim() : '';
      const outerNote = typeof targetObj.b === 'string' ? targetObj.b.trim() : typeof outerObj.b === 'string' ? outerObj.b.trim() : '';
      const outerExpiryStr = typeof targetObj.c === 'string' ? targetObj.c.trim() : typeof outerObj.c === 'string' ? outerObj.c.trim() : '';

      // Parse YYYY-MM-DD expiry date into epoch ms (end of day UTC)
      let expiryMs = 0;
      if (outerExpiryStr && /^\d{4}-\d{2}-\d{2}/.test(outerExpiryStr)) {
        const parsedMs = Date.parse(
          outerExpiryStr.includes('T') ? outerExpiryStr : `${outerExpiryStr}T23:59:59Z`
        );
        if (!Number.isNaN(parsedMs)) expiryMs = parsedMs;
      }

      // Map SSH Custom mode to the corresponding Tweve Tunnel connection type so all validation & live probes run
      const hasDnstt = Boolean(primary.NS_SERVER || primary.PUBKEY || primary.PROTOCOL_ID === 1);
      const hasPayload = Boolean(primary.PAYLOAD);
      const hasProxy = Boolean(primary.PROXY);
      const isTls = String(primary.TUNNEL_TYPE || '').toUpperCase() === 'TLS';

      let mappedTunnelType = 0; // SSH Direct
      if (hasDnstt) {
        mappedTunnelType = 6; // SlowDNS (DNSTT) over SSH
      } else if (isTls && hasPayload && hasProxy) {
        mappedTunnelType = 7; // SSH + Proxy + Payload + SSL
      } else if (isTls && hasPayload) {
        mappedTunnelType = 3; // SSH + SSL + Payload
      } else if (isTls) {
        mappedTunnelType = 2; // SSH + SSL (TLS/Stunnel)
      } else if (hasProxy && hasPayload) {
        mappedTunnelType = 5; // SSH + HTTP Proxy + Payload
      } else if (hasProxy) {
        mappedTunnelType = 4; // SSH + HTTP Proxy
      } else if (hasPayload) {
        mappedTunnelType = 1; // SSH + HTTP Payload
      }

      const bannerParts = [primary.CONFIG_NAME, outerTitle, outerNote].filter(Boolean);
      const sha256Hash = crypto.createHash('sha256').update(outerBytes).digest('hex');

      return {
        decryptedJson: {
          config_version: `SSC-v${targetObj.d ?? outerObj.d ?? primary.VERSION ?? 96}`,
          config_message: bannerParts.join(' — ') || 'SSH Custom (Ssc://) Decrypted Configuration',
          config_expiry: expiryMs,
          config_expiry_date_str: outerExpiryStr || 'No Expiry',
          config_protected: Boolean(
            primary.HWID_LOCK || primary.ROOT_LOCK || primary.PLAYSTORE_LOCK || primary.EXPIRY_LOCK || primary.PASSWORD_LOCK
          ),
          hide_ssh_credentials: false,
          hide_proxy_settings: false,
          block_rooted: Boolean(primary.ROOT_LOCK),
          hwid_enabled: Boolean(primary.HWID_LOCK),
          tunnelType: mappedTunnelType,
          type: String(mappedTunnelType),
          // Normalized SSH fields
          sshServer: primary.SNI_OR_HOST || primary.DNS_RESOLVER || '',
          sshPort: String(primary.PORT || 22),
          sshAltPort: String(primary.SSH_PORT || 2222),
          sshUser: primary.USERNAME || '',
          sshPass: primary.PASSWORD || '',
          sslPort: String(primary.PORT || 443),
          // Normalized Proxy / Payload / SSL SNI fields
          sni: primary.SNI_OR_HOST || '',
          payload: primary.PAYLOAD || '',
          proxyHost: primary.PROXY || '',
          proxyPort: String(primary.PROXY_PORT || '8080'),
          // Normalized SlowDNS (DNSTT) fields
          nameserver: primary.NS_SERVER || '',
          pubkey: primary.PUBKEY || '',
          dnsresolver: primary.DNS_RESOLVER || '8.8.8.8',
          dnstt_record_type: 'TXT',
          // Normalized Network / UDPGW fields
          dns1: primary.DNS_RESOLVER || '8.8.8.8',
          dns2: '8.8.4.4',
          udpgwPort: String(primary.UDPGW_PORT || 7300),
          udpResolver: `127.0.0.1:${primary.UDPGW_PORT || 7300}`,
          // Full SSH Custom metadata & decrypted profiles
          is_ssc_container: true,
          ssc_container: {
            scheme: hasSscScheme ? 'Ssc://' : '.ssc File',
            appName: 'SSH Custom (ePro Dev Team)',
            decryptedSuccessfully: true,
            usedNestedLockLayer: usedNestedLayer,
            hexLength: compactHex.length,
            byteLength: outerBytes.length,
            sha256Fingerprint: sha256Hash,
            outerAuthorTitle: outerTitle,
            outerBannerNote: outerNote,
            outerExpiryDate: outerExpiryStr || 'None',
            outerVersion: targetObj.d ?? outerObj.d ?? 96,
            profileCount: remappedProfiles.length,
            generatedSscUri: `Ssc://${hexCandidate.split('').reverse().join('')}`,
            rawSscFileHex: hexCandidate,
            profiles: remappedProfiles,
          },
        },
        encryptionMethod: `SSH Custom Ssc:// 3-Layer ChaCha20Legacy-Poly1305 AEAD (${
          usedNestedLayer ? 'L1 + L2 Nested Lock + L3 Field Cipher' : 'L1 Outer AEAD + L3 Per-Field Cipher'
        })`,
      };
    } catch {
      // Try next candidate
    }
  }

  return null;
}

function tryParseCreebInput(raw: string): {
  decryptedJson: Record<string, any>;
  encryptionMethod: string;
} | null {
  const trimmed = raw.trim();

  // 1. Check for Emoji Cloud Token: 💉<emojis>🚀 (starts with U+1F489 💉 and ends with U+1F680 🚀, or 8+ emojis in U+1F600..U+1F64F)
  const codepoints = [...trimmed].map((ch) => ch.codePointAt(0) || 0);
  const isSyringeRocketEmojiToken =
    codepoints.length >= 6 &&
    codepoints.length <= 64 &&
    (codepoints[0] === 0x1f489 || codepoints.every((cp) => cp >= 0x1f300 && cp <= 0x1f9ff));

  if (isSyringeRocketEmojiToken) {
    const hasSyringePrefix = codepoints[0] === 0x1f489;
    const hasRocketSuffix = codepoints[codepoints.length - 1] === 0x1f680;
    const bodyCodepoints = codepoints.slice(
      hasSyringePrefix ? 1 : 0,
      hasRocketSuffix ? codepoints.length - 1 : codepoints.length
    );
    const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
    const offsets = bodyCodepoints.map((cp) => cp - 0x1f600);
    const mappedBase62 = offsets
      .map((off) => (off >= 0 && off < BASE62.length ? BASE62[off] : `?`))
      .join('');
    const hexOffsets = bodyCodepoints.map((cp) => `U+${cp.toString(16).toUpperCase()}`).join(' ');

    return {
      decryptedJson: {
        config_version: 'EMOJI-CLOUD-v1',
        config_message: `Emoji Cloud Token (${trimmed}) — ${bodyCodepoints.length}-Emoji Short ID (${offsets.join(', ')})`,
        config_protected: false,
        hide_ssh_credentials: false,
        hide_proxy_settings: false,
        tunnelType: 15,
        type: '15',
        is_creeb_container: true,
        creeb_container: {
          fullToken: trimmed,
          prefix: hasSyringePrefix ? '💉 (U+1F489)...🚀 (U+1F680)' : 'EMOJI-ID',
          shortId: `Offsets: [${offsets.join(', ')}] (Base62: ${mappedBase62})`,
          idLength: bodyCodepoints.length,
          appName: `Emoji Cloud Config (${hexOffsets})`,
          supportedProtocols: [
            'DIRECT',
            'SSL/TLS',
            'HTTP PROXY',
            'SSL PAYLOAD',
            'SSL WEBSOCKET',
            'DNSTT (SlowDNS)',
            'UDP (HYSTERIA)',
            'V2RAY',
          ],
          resolutionNote:
            `This ${bodyCodepoints.length}-emoji string (${trimmed}) encodes only ${bodyCodepoints.length} numbers [${offsets.join(', ')}] (~9 bytes total). Like CREEBINJ-XOgE1Ufri26q, it is a short database lookup ID — the actual SSH/SlowDNS/V2Ray server settings are stored on the VPN app's private cloud database, not inside the 12 emojis. To inspect all configuration fields automatically, export the config as a local file (.twt / .tut / .ssc) or provide your Custom Cloud API URL below.`,
        },
      },
      encryptionMethod: `Emoji Short Cloud ID (${bodyCodepoints.length} Emojis wrapped in 💉...🚀)`,
    };
  }

  // 2. Check for CREEBINJ-<ID> text token
  const m = trimmed.match(/^(CREEBINJ)-([A-Za-z0-9_-]{4,64})$/i);
  if (!m) return null;

  const prefix = m[1].toUpperCase();
  const shortId = m[2];
  const fullToken = `${prefix}-${shortId}`;

  return {
    decryptedJson: {
      config_version: 'CREEB-v38',
      config_message: `Creeb Injector Cloud Token (${fullToken})`,
      config_protected: false,
      hide_ssh_credentials: false,
      hide_proxy_settings: false,
      tunnelType: 15,
      type: '15',
      is_creeb_container: true,
      creeb_container: {
        fullToken,
        prefix,
        shortId,
        idLength: shortId.length,
        appName: 'CREEB INJECTOR (com.creeb.Injector)',
        supportedProtocols: [
          'DIRECT',
          'SSL/TLS',
          'HTTP PROXY',
          'SSL PAYLOAD',
          'SSL WEBSOCKET',
          'DNSTT (SlowDNS)',
          'UDP (HYSTERIA)',
          'V2RAY',
        ],
        resolutionNote:
          'CREEBINJ-<ID> is a 12-character server-side Cloud Reference ID (not an inline encrypted payload like Ssc:// or .twt). Enter your Custom Cloud API URL or the target Server IP / SNI / SlowDNS Nameserver below to verify the full configuration and live server reachability.',
      },
    },
    encryptionMethod: `Creeb Injector Cloud Reference Token (${fullToken})`,
  };
}

function tryDecryptAny(rawPayload: string, passphrase?: string): {
  decryptedJson: Record<string, any> | null;
  encryptionMethod: string;
  error?: string;
} {
  const clean = rawPayload.trim();

  // Check if Ssc:// hex URI or .ssc file
  const sscResult = tryDecryptSscPayload(clean, passphrase);
  if (sscResult) {
    return sscResult;
  }

  // Check if CREEBINJ-<ID> cloud reference token
  const creebResult = tryParseCreebInput(clean);
  if (creebResult) {
    return creebResult;
  }

  // Check if direct protocol link (vless://, vmess://, trojan://, hy2://, WireGuard)
  const directProto = tryParseDirectProtocolInput(clean);
  if (directProto) {
    return {
      decryptedJson: directProto.parsed,
      encryptionMethod: directProto.methodLabel,
    };
  }

  // Check if plain JSON
  if (clean.startsWith('{') && clean.endsWith('}')) {
    try {
      const parsed = JSON.parse(clean);
      if (parsed && typeof parsed === 'object' && typeof parsed.config === 'string' && Object.keys(parsed).length <= 3) {
        return tryDecryptAny(parsed.config, passphrase);
      }
      // Also check if it's a raw Xray/V2Ray config with "outbounds"
      if (Array.isArray(parsed.outbounds)) {
        const ob = parsed.outbounds.find((o: any) => ['vless', 'vmess', 'trojan', 'shadowsocks'].includes(o.protocol)) || parsed.outbounds[0] || {};
        const vnext = ob.settings?.vnext?.[0] || ob.settings?.servers?.[0] || {};
        const user = vnext.users?.[0] || {};
        const stream = ob.streamSettings || {};
        const tlsSettings = stream.tlsSettings || stream.realitySettings || {};
        const wsSettings = stream.wsSettings || {};
        return {
          decryptedJson: {
            config_version: 7,
            config_message: ob.tag || 'Raw Xray/V2Ray JSON Config',
            tunnelType: 9,
            type: '9',
            v2ray_protocol: ob.protocol || 'vless',
            v2ray_server_host: vnext.address || '',
            v2ray_server_port: String(vnext.port || '443'),
            v2ray_uuid: user.id || vnext.password || '',
            v2ray_security: stream.security || 'none',
            v2ray_network: stream.network || 'tcp',
            v2ray_sni: tlsSettings.serverName || '',
            v2ray_ws_host: wsSettings.headers?.Host || '',
            v2ray_ws_path: wsSettings.path || '/',
            v2ray_public_key: stream.realitySettings?.publicKey || '',
            v2ray_short_id: stream.realitySettings?.shortId || '',
            v2ray_raw_config: clean,
          },
          encryptionMethod: 'Raw Xray/V2Ray Outbound JSON',
        };
      }
      return { decryptedJson: parsed, encryptionMethod: 'Plain JSON (Unencrypted)' };
    } catch {
      // continue
    }
  }

  if (clean.startsWith(PASSPHRASE_PREFIX)) {
    if (!passphrase) {
      return {
        decryptedJson: null,
        encryptionMethod: 'TTPBE1 (PBKDF2-SHA256 + AES-256-GCM Passphrase)',
        error: 'This configuration is locked with a custom passphrase (TTPBE1). Please enter the passphrase to decrypt it.',
      };
    }
    const dec = decryptWithPassphrase(clean, passphrase);
    if (dec) {
      try {
        return {
          decryptedJson: JSON.parse(dec),
          encryptionMethod: 'TTPBE1 (PBKDF2-SHA256 120k iter + AES-256-GCM)',
        };
      } catch {
        // continue
      }
    }
    return {
      decryptedJson: null,
      encryptionMethod: 'TTPBE1 (PBKDF2-SHA256 + AES-256-GCM Passphrase)',
      error: 'Invalid passphrase or corrupted TTPBE1 ciphertext.',
    };
  }

  const aesDec = decryptAES(clean);
  if (aesDec) {
    try {
      return {
        decryptedJson: JSON.parse(aesDec),
        encryptionMethod: 'Standard TweveTunnel AES-128-CBC (Key: TunnelTweak2024!)',
      };
    } catch {
      // continue
    }
  }

  const secDec = decryptSecureConfig(clean);
  if (secDec) {
    try {
      return {
        decryptedJson: JSON.parse(secDec),
        encryptionMethod: 'SecureConfigEncryption AES-256-GCM (PBKDF2 TunnelTweak-Secure-v1)',
      };
    } catch {
      // continue
    }
  }

  if (passphrase) {
    const passDec = decryptWithPassphrase(clean, passphrase);
    if (passDec) {
      try {
        return {
          decryptedJson: JSON.parse(passDec),
          encryptionMethod: 'Passphrase AES-256-GCM',
        };
      } catch {
        // continue
      }
    }
  }

  const xorDec = decryptLegacyXOR(clean);
  if (xorDec) {
    try {
      return {
        decryptedJson: JSON.parse(xorDec),
        encryptionMethod: 'Legacy XOR (0x5A) + Base64',
      };
    } catch {
      // continue
    }
  }

  try {
    const plainB64 = Buffer.from(clean, 'base64').toString('utf8');
    if (plainB64.trim().startsWith('{')) {
      return {
        decryptedJson: JSON.parse(plainB64),
        encryptionMethod: 'Base64-Encoded JSON',
      };
    }
  } catch {
    // ignore
  }

  return {
    decryptedJson: null,
    encryptionMethod: 'Unknown',
    error: 'Could not decrypt or parse configuration. Ensure it is a valid Cloud UUID, .twt/.tut payload, V2Ray URI (vless://, vmess://, trojan://), Hysteria2 URI (hy2://), or WireGuard config.',
  };
}

function probeTcpPort(host: string, port: number, timeoutMs = 4000): Promise<{
  reachable: boolean;
  latencyMs: number | null;
  banner: string | null;
  error: string | null;
}> {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = new net.Socket();
    let banner: string | null = null;
    let settled = false;

    const finish = (reachable: boolean, error: string | null) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({
        reachable,
        latencyMs: reachable ? Date.now() - start : null,
        banner,
        error,
      });
    };

    socket.setTimeout(timeoutMs);

    socket.on('connect', () => {
      setTimeout(() => {
        finish(true, null);
      }, 650);
    });

    socket.on('data', (data) => {
      banner = data.toString('utf8').trim().slice(0, 200);
      finish(true, null);
    });

    socket.on('timeout', () => {
      finish(false, `Connection timed out (${timeoutMs}ms)`);
    });

    socket.on('error', (err: any) => {
      finish(false, err.message || 'TCP connection failed');
    });

    try {
      socket.connect(port, host);
    } catch (e: any) {
      finish(false, e?.message || 'Invalid host/port');
    }
  });
}

/**
 * Live TLS / SNI Handshake Probe:
 * Connects to host:port using TLS with the configured SNI (Server Name Indication)
 * and extracts the TLS protocol version, cipher suite, ALPN, and X.509 certificate metadata.
 */
function probeTlsHandshake(host: string, port: number, servername: string, timeoutMs = 4500): Promise<{
  success: boolean;
  latencyMs: number | null;
  sniSent: string;
  protocol: string | null;
  cipher: string | null;
  alpnProtocol: string | null;
  authorized: boolean;
  authorizationError: string | null;
  certSubject: string | null;
  certIssuer: string | null;
  certValidFrom: string | null;
  certValidTo: string | null;
  certDaysRemaining: number | null;
  certAltNames: string[];
  error: string | null;
}> {
  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;

    const finish = (res: any) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {}
      resolve(res);
    };

    const sni = (servername || host).trim();
    const socket = tls.connect(
      {
        host,
        port,
        servername: net.isIP(sni) ? undefined : sni,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
        timeout: timeoutMs,
      },
      () => {
        const latencyMs = Date.now() - start;
        const cert = socket.getPeerCertificate(false);
        const cipherObj = socket.getCipher();
        const proto = socket.getProtocol();
        const alpn = socket.alpnProtocol || null;
        let daysRemaining: number | null = null;
        if (cert && cert.valid_to) {
          const expiryMs = Date.parse(cert.valid_to);
          if (!isNaN(expiryMs)) {
            daysRemaining = Math.floor((expiryMs - Date.now()) / 86400000);
          }
        }
        const altNames = cert?.subjectaltname
          ? cert.subjectaltname.split(',').map((s: string) => s.trim().replace(/^DNS:/i, '')).slice(0, 8)
          : [];

        finish({
          success: true,
          latencyMs,
          sniSent: sni,
          protocol: proto || null,
          cipher: cipherObj ? `${cipherObj.name} (${cipherObj.version})` : null,
          alpnProtocol: alpn ? String(alpn) : null,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
          certSubject: cert?.subject?.CN || cert?.subject?.O || null,
          certIssuer: cert?.issuer?.CN || cert?.issuer?.O || null,
          certValidFrom: cert?.valid_from || null,
          certValidTo: cert?.valid_to || null,
          certDaysRemaining: daysRemaining,
          certAltNames: altNames,
          error: null,
        });
      }
    );

    socket.setTimeout(timeoutMs);
    socket.on('timeout', () => {
      finish({
        success: false,
        latencyMs: null,
        sniSent: sni,
        protocol: null,
        cipher: null,
        alpnProtocol: null,
        authorized: false,
        authorizationError: null,
        certSubject: null,
        certIssuer: null,
        certValidFrom: null,
        certValidTo: null,
        certDaysRemaining: null,
        certAltNames: [],
        error: `TLS handshake timed out after ${timeoutMs}ms`,
      });
    });

    socket.on('error', (err: any) => {
      finish({
        success: false,
        latencyMs: null,
        sniSent: sni,
        protocol: null,
        cipher: null,
        alpnProtocol: null,
        authorized: false,
        authorizationError: null,
        certSubject: null,
        certIssuer: null,
        certValidFrom: null,
        certValidTo: null,
        certDaysRemaining: null,
        certAltNames: [],
        error: err?.message || 'TLS handshake failed',
      });
    });
  });
}

/**
 * Live WebSocket / HTTP Upgrade Probe for V2Ray WS or HTTP Payload endpoints:
 * Sends a WebSocket Upgrade or custom HTTP payload over TCP or TLS and reads the HTTP response status & headers.
 */
function probeHttpOrWsUpgrade(options: {
  host: string;
  port: number;
  useTls: boolean;
  sni: string;
  wsHost: string;
  wsPath: string;
  customPayload?: string;
  timeoutMs?: number;
}): Promise<{
  responded: boolean;
  latencyMs: number | null;
  statusLine: string | null;
  statusCode: number | null;
  serverHeader: string | null;
  cfRay: string | null;
  upgradeAccepted: boolean;
  rawHeadersPreview: string | null;
  requestSentPreview: string;
  error: string | null;
}> {
  const timeoutMs = options.timeoutMs ?? 4500;
  const hostHeader = (options.wsHost || options.sni || options.host).trim();
  const pathStr = (options.wsPath || '/').startsWith('/') ? (options.wsPath || '/') : `/${options.wsPath}`;
  const wsKey = crypto.randomBytes(16).toString('base64');

  const requestLines = options.customPayload
    ? options.customPayload
    : [
        `GET ${pathStr} HTTP/1.1`,
        `Host: ${hostHeader}`,
        `User-Agent: Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile`,
        `Upgrade: websocket`,
        `Connection: Upgrade`,
        `Sec-WebSocket-Key: ${wsKey}`,
        `Sec-WebSocket-Version: 13`,
        ``,
        ``,
      ].join('\r\n');

  return new Promise((resolve) => {
    const start = Date.now();
    let settled = false;
    let socket: net.Socket | tls.TLSSocket;

    const finish = (res: any) => {
      if (settled) return;
      settled = true;
      try {
        socket.destroy();
      } catch {}
      resolve(res);
    };

    const onConnected = () => {
      try {
        socket.write(requestLines);
      } catch (e: any) {
        finish({
          responded: false,
          latencyMs: null,
          statusLine: null,
          statusCode: null,
          serverHeader: null,
          cfRay: null,
          upgradeAccepted: false,
          rawHeadersPreview: null,
          requestSentPreview: requestLines.trim(),
          error: e?.message || 'Failed to write HTTP probe',
        });
      }
    };

    if (options.useTls) {
      const sni = (options.sni || options.wsHost || options.host).trim();
      socket = tls.connect(
        {
          host: options.host,
          port: options.port,
          servername: net.isIP(sni) ? undefined : sni,
          rejectUnauthorized: false,
          ALPNProtocols: ['http/1.1'],
          timeout: timeoutMs,
        },
        onConnected
      );
    } else {
      socket = new net.Socket();
      socket.setTimeout(timeoutMs);
      socket.connect(options.port, options.host, onConnected);
    }

    socket.setTimeout(timeoutMs);

    socket.on('data', (chunk) => {
      const latencyMs = Date.now() - start;
      const text = chunk.toString('utf8');
      const headerBlock = text.split('\r\n\r\n')[0] || text.slice(0, 500);
      const lines = headerBlock.split('\r\n');
      const statusLine = lines[0]?.trim() || null;
      const codeMatch = statusLine?.match(/^HTTP\/\d\.\d\s+(\d{3})/i);
      const statusCode = codeMatch ? parseInt(codeMatch[1], 10) : null;

      let serverHeader: string | null = null;
      let cfRay: string | null = null;
      for (const line of lines.slice(1)) {
        const [k, ...vParts] = line.split(':');
        if (!k || !vParts.length) continue;
        const val = vParts.join(':').trim();
        if (k.toLowerCase() === 'server') serverHeader = val;
        if (k.toLowerCase() === 'cf-ray') cfRay = val;
      }

      finish({
        responded: true,
        latencyMs,
        statusLine,
        statusCode,
        serverHeader,
        cfRay,
        upgradeAccepted: statusCode === 101 || statusCode === 200,
        rawHeadersPreview: headerBlock.slice(0, 450),
        requestSentPreview: requestLines.trim(),
        error: null,
      });
    });

    socket.on('timeout', () => {
      finish({
        responded: false,
        latencyMs: null,
        statusLine: null,
        statusCode: null,
        serverHeader: null,
        cfRay: null,
        upgradeAccepted: false,
        rawHeadersPreview: null,
        requestSentPreview: requestLines.trim(),
        error: `HTTP/WS probe timed out (${timeoutMs}ms)`,
      });
    });

    socket.on('error', (err: any) => {
      finish({
        responded: false,
        latencyMs: null,
        statusLine: null,
        statusCode: null,
        serverHeader: null,
        cfRay: null,
        upgradeAccepted: false,
        rawHeadersPreview: null,
        requestSentPreview: requestLines.trim(),
        error: err?.message || 'HTTP/WS probe connection error',
      });
    });
  });
}

function probeDnsOverUdp(resolverIp: string, domain: string, timeoutMs = 3500): Promise<{
  reachable: boolean;
  latencyMs: number | null;
  rcode: number | null;
  answerCount: number | null;
  error: string | null;
}> {
  return new Promise((resolve) => {
    const cleanHost = resolverIp.includes(':') ? resolverIp.split(':')[0] : resolverIp;
    const port = resolverIp.includes(':') ? parseInt(resolverIp.split(':')[1], 10) || 53 : 53;

    const client = dgram.createSocket('udp4');
    const start = Date.now();
    let settled = false;

    const finish = (reachable: boolean, rcode: number | null, answerCount: number | null, error: string | null) => {
      if (settled) return;
      settled = true;
      try {
        client.close();
      } catch {}
      resolve({
        reachable,
        latencyMs: reachable ? Date.now() - start : null,
        rcode,
        answerCount,
        error,
      });
    };

    const timer = setTimeout(() => {
      finish(false, null, null, `UDP DNS query timed out (${timeoutMs}ms)`);
    }, timeoutMs);

    const txid = crypto.randomBytes(2);
    const flags = Buffer.from([0x01, 0x20]);
    const counts = Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const labels = domain
      .replace(/\.$/, '')
      .split('.')
      .filter(Boolean)
      .map((label) => {
        const b = Buffer.from(label, 'utf8');
        return Buffer.concat([Buffer.from([b.length]), b]);
      });
    const qname = Buffer.concat([...labels, Buffer.from([0x00])]);
    const qtypeClass = Buffer.from([0x00, 0x10, 0x00, 0x01]);
    const packet = Buffer.concat([txid, flags, counts, qname, qtypeClass]);

    client.on('message', (msg) => {
      clearTimeout(timer);
      if (msg.length >= 12) {
        const rcode = msg[3] & 0x0f;
        const ancount = msg.readUInt16BE(6);
        finish(true, rcode, ancount, null);
      } else {
        finish(true, null, null, null);
      }
    });

    client.on('error', (err) => {
      clearTimeout(timer);
      finish(false, null, null, err.message);
    });

    try {
      client.send(packet, port, cleanHost);
    } catch (e: any) {
      clearTimeout(timer);
      finish(false, null, null, e?.message || 'UDP send failed');
    }
  });
}

async function resolveDomainDetails(domain: string) {
  if (!domain || !domain.trim()) {
    return { domain, ipv4: [], ns: [], txt: [], error: 'Empty domain' };
  }
  const clean = domain.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0];
  if (net.isIP(clean)) {
    return { domain: clean, ipv4: [clean], ns: [], txt: [], isIpLiteral: true, error: null };
  }

  const [ipv4, ns, txtRaw] = await Promise.all([
    withTimeout(dns.resolve4(clean).catch(() => [] as string[]), 2200, [] as string[]),
    withTimeout(dns.resolveNs(clean).catch(() => [] as string[]), 2200, [] as string[]),
    withTimeout(dns.resolveTxt(clean).catch(() => [] as string[][]), 2200, [] as string[][]),
  ]);
  const txt = txtRaw.map((chunks) => chunks.join('')).slice(0, 5);

  return {
    domain: clean,
    ipv4,
    ns,
    txt,
    isIpLiteral: false,
    error: ipv4.length === 0 && ns.length === 0 && txt.length === 0 ? 'No DNS records (A/NS/TXT) resolved within timeout' : null,
  };
}

/**
 * Expands a Tweve Tunnel HTTP Payload template (with [host], [port], [crlf], [split], [ua], etc.)
 * into the actual raw HTTP wire string so the user can inspect exactly what gets injected.
 */
function expandHttpPayloadTemplate(template: string, sshHost: string, sshPort: string, sniHost: string): {
  expandedPreview: string;
  wireRequest: string;
  detectedTokens: string[];
  splitCount: number;
} {
  if (!template || !template.trim()) {
    return { expandedPreview: '', wireRequest: '', detectedTokens: [], splitCount: 0 };
  }
  const targetHost = sshHost || sniHost || 'example.com';
  const targetPort = sshPort || '22';
  const tokens: string[] = [];
  const tokenRegex = /\[[a-zA-Z0-9_]+\]/g;
  let m: RegExpExecArray | null;
  while ((m = tokenRegex.exec(template)) !== null) {
    if (!tokens.includes(m[0])) tokens.push(m[0]);
  }

  const splitMatches = template.match(/\[(split|instant_split|delay_split)\]/gi);
  const splitCount = splitMatches ? splitMatches.length : 0;

  const replaceCommon = (str: string, visualNewlines: boolean) => {
    const crlf = visualNewlines ? '\n' : '\r\n';
    return str
      .replace(/\[host_port\]/gi, `${targetHost}:${targetPort}`)
      .replace(/\[host\]/gi, targetHost)
      .replace(/\[port\]/gi, targetPort)
      .replace(/\[sni\]/gi, sniHost || targetHost)
      .replace(/\[method\]/gi, 'CONNECT')
      .replace(/\[protocol\]/gi, 'HTTP/1.1')
      .replace(/\[http_version\]/gi, 'HTTP/1.1')
      .replace(/\[ua\]/gi, 'Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36')
      .replace(/\[(split|instant_split|delay_split)\]/gi, visualNewlines ? '\n--- [PACKET SPLIT] ---\n' : '')
      .replace(/\[crlf\]\[crlf\]/gi, `${crlf}${crlf}`)
      .replace(/\[crlf\]/gi, crlf)
      .replace(/\[lf\]/gi, '\n')
      .replace(/\[cr\]/gi, '\r')
      .replace(/\[sp\]/gi, ' ');
  };

  return {
    expandedPreview: replaceCommon(template, true),
    wireRequest: replaceCommon(template, false),
    detectedTokens: tokens,
    splitCount,
  };
}

/**
 * Generates standard V2Ray share URI (vless://, vmess://, trojan://) and Xray Outbound JSON
 * from the config's V2Ray parameters for easy cross-client verification.
 */
function buildV2RayArtifacts(v2: {
  protocol: string;
  serverHost: string;
  serverPort: string;
  uuid: string;
  alterId: string;
  security: string;
  network: string;
  sni: string;
  wsHost: string;
  wsPath: string;
  publicKey: string;
  shortId: string;
  allowInsecure: boolean;
  domainStrategy: string;
  remark: string;
}) {
  const proto = (v2.protocol || 'vless').toLowerCase();
  const host = v2.serverHost || 'server.example.com';
  const port = parseInt(v2.serverPort || '443', 10) || 443;
  const uuid = v2.uuid || '';
  const netType = v2.network || 'tcp';
  const sec = v2.security || 'none';
  const sni = v2.sni || v2.wsHost || host;
  const wsHost = v2.wsHost || sni;
  const wsPath = v2.wsPath || '/';
  const remarkEncoded = encodeURIComponent(v2.remark || `TweveTunnel-${proto.toUpperCase()}`);

  let shareUri = '';
  if (proto === 'vmess') {
    const vmessObj = {
      v: '2',
      ps: v2.remark || 'TweveTunnel-VMess',
      add: host,
      port: String(port),
      id: uuid,
      aid: v2.alterId || '0',
      scy: 'auto',
      net: netType,
      type: 'none',
      host: wsHost,
      path: wsPath,
      tls: sec === 'tls' ? 'tls' : '',
      sni,
    };
    shareUri = `vmess://${Buffer.from(JSON.stringify(vmessObj), 'utf8').toString('base64')}`;
  } else {
    const params = new URLSearchParams();
    params.set('type', netType);
    params.set('security', sec);
    if (sec === 'tls' || sec === 'reality') {
      if (sni) params.set('sni', sni);
      if (v2.allowInsecure) params.set('allowInsecure', '1');
    }
    if (sec === 'reality') {
      if (v2.publicKey) params.set('pbk', v2.publicKey);
      if (v2.shortId) params.set('sid', v2.shortId);
      params.set('fp', 'chrome');
    }
    if (netType === 'ws') {
      if (wsHost) params.set('host', wsHost);
      if (wsPath) params.set('path', wsPath);
    } else if (netType === 'grpc') {
      if (wsPath && wsPath !== '/') params.set('serviceName', wsPath.replace(/^\//, ''));
    }
    shareUri = `${proto}://${encodeURIComponent(uuid)}@${host}:${port}?${params.toString()}#${remarkEncoded}`;
  }

  const xrayOutbound: Record<string, any> = {
    tag: 'proxy',
    protocol: proto,
    settings:
      proto === 'trojan'
        ? { servers: [{ address: host, port, password: uuid }] }
        : {
            vnext: [
              {
                address: host,
                port,
                users: [
                  proto === 'vmess'
                    ? { id: uuid, alterId: parseInt(v2.alterId || '0', 10) || 0, security: 'auto' }
                    : { id: uuid, encryption: 'none' },
                ],
              },
            ],
          },
    streamSettings: {
      network: netType,
      security: sec,
      ...(sec === 'tls'
        ? {
            tlsSettings: {
              serverName: sni,
              allowInsecure: Boolean(v2.allowInsecure),
              alpn: netType === 'ws' ? ['http/1.1'] : ['h2', 'http/1.1'],
            },
          }
        : {}),
      ...(sec === 'reality'
        ? {
            realitySettings: {
              serverName: sni,
              publicKey: v2.publicKey,
              shortId: v2.shortId,
              fingerprint: 'chrome',
            },
          }
        : {}),
      ...(netType === 'ws'
        ? {
            wsSettings: {
              path: wsPath,
              headers: wsHost ? { Host: wsHost } : {},
            },
          }
        : {}),
    },
  };

  return { shareUri, xrayOutbound };
}

/**
 * Parses WireGuard INI configuration into structured Interface and Peer fields + validation checks.
 */
function parseWireGuardIni(iniText: string) {
  if (!iniText || !iniText.trim()) return null;
  const lines = iniText.split(/\r?\n/);
  let currentSection: 'interface' | 'peer' | null = null;
  const iface: Record<string, string> = {};
  const peer: Record<string, string> = {};

  for (const rawLine of lines) {
    const line = rawLine.replace(/#.*$/, '').trim();
    if (!line) continue;
    if (/^\[Interface\]$/i.test(line)) {
      currentSection = 'interface';
      continue;
    }
    if (/^\[Peer\]$/i.test(line)) {
      currentSection = 'peer';
      continue;
    }
    const eqIdx = line.indexOf('=');
    if (eqIdx > 0 && currentSection) {
      const k = line.slice(0, eqIdx).trim();
      const v = line.slice(eqIdx + 1).trim();
      if (currentSection === 'interface') iface[k] = v;
      if (currentSection === 'peer') peer[k] = v;
    }
  }

  const endpoint = peer.Endpoint || peer.endpoint || '';
  let endpointHost = '';
  let endpointPort = 51820;
  if (endpoint) {
    const lastColon = endpoint.lastIndexOf(':');
    if (lastColon > 0) {
      endpointHost = endpoint.slice(0, lastColon).replace(/^\[|\]$/g, '');
      endpointPort = parseInt(endpoint.slice(lastColon + 1), 10) || 51820;
    } else {
      endpointHost = endpoint;
    }
  }

  const privKey = iface.PrivateKey || '';
  const pubKey = peer.PublicKey || '';
  const validPrivKey = /^[A-Za-z0-9+/]{43}=$/.test(privKey);
  const validPubKey = /^[A-Za-z0-9+/]{43}=$/.test(pubKey);

  return {
    interface: {
      privateKeyMasked: privKey ? `${privKey.slice(0, 6)}...${privKey.slice(-4)}` : '',
      privateKeyFull: privKey,
      validPrivateKey: validPrivKey,
      address: iface.Address || '',
      dns: iface.DNS || '',
      mtu: iface.MTU || '1420',
    },
    peer: {
      publicKey: pubKey,
      validPublicKey: validPubKey,
      presharedKeyPresent: Boolean(peer.PresharedKey),
      endpoint,
      endpointHost,
      endpointPort,
      allowedIPs: peer.AllowedIPs || '0.0.0.0/0, ::/0',
      persistentKeepalive: peer.PersistentKeepalive || '25',
    },
  };
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const {
      input,
      passphrase,
      runNetworkProbes = true,
      manualServerHost,
      manualServerPort,
      manualSni,
      manualNameserver,
      customCloudUrl,
    } = body as {
      input?: string;
      passphrase?: string;
      runNetworkProbes?: boolean;
      manualServerHost?: string;
      manualServerPort?: string;
      manualSni?: string;
      manualNameserver?: string;
      customCloudUrl?: string;
    };

    if (!input || !input.trim()) {
      return NextResponse.json({ error: 'Please provide a Cloud Config UUID, URL, V2Ray/Hysteria2 link, or .twt/.tut content.' }, { status: 400 });
    }

    const trimmed = input.trim();
    let rawEncryptedContent = trimmed;
    let cloudMeta: {
      isCloudFetch: boolean;
      uuid: string | null;
      endpointUrl: string | null;
      httpStatus: number | null;
      fetchTimeMs: number | null;
    } = {
      isCloudFetch: false,
      uuid: null,
      endpointUrl: null,
      httpStatus: null,
      fetchTimeMs: null,
    };

    // Match UUID if not a vless:// / vmess:// / trojan:// / hy2:// URI
    const isDirectUri = /^(vless|vmess|trojan|ss|hy2|hysteria2):\/\//i.test(trimmed);
    const uuidRegex = /([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/;
    const uuidMatch = !isDirectUri && !trimmed.startsWith('{') ? trimmed.match(uuidRegex) : null;

    if (customCloudUrl && /^https?:\/\//i.test(customCloudUrl.trim())) {
      const targetUrl = customCloudUrl.trim();
      cloudMeta.isCloudFetch = true;
      cloudMeta.uuid = trimmed;
      cloudMeta.endpointUrl = targetUrl;
      const fetchStart = Date.now();
      const resp = await fetch(targetUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'CreebInjector/38.0 (Android; CloudInspector)',
          Accept: 'application/json, text/plain, */*',
        },
        cache: 'no-store',
      });
      cloudMeta.httpStatus = resp.status;
      cloudMeta.fetchTimeMs = Date.now() - fetchStart;
      if (!resp.ok) {
        return NextResponse.json(
          {
            error: `Custom Cloud URL returned HTTP ${resp.status} when fetching "${targetUrl}".`,
            cloudMeta,
          },
          { status: resp.status === 404 ? 404 : 502 }
        );
      }
      const bodyText = (await resp.text()).trim();
      try {
        const parsedJson = JSON.parse(bodyText);
        if (typeof parsedJson.config === 'string' && parsedJson.config.trim()) {
          rawEncryptedContent = parsedJson.config.trim();
        } else if (typeof parsedJson.data === 'string' && parsedJson.data.trim()) {
          rawEncryptedContent = parsedJson.data.trim();
        } else {
          rawEncryptedContent = bodyText;
        }
      } catch {
        rawEncryptedContent = bodyText;
      }
    } else if (uuidMatch && (trimmed.length <= 120 || trimmed.startsWith('http'))) {
      const uuid = uuidMatch[1].toLowerCase();
      const url = `${CLOUD_API_BASE}/${uuid}`;
      cloudMeta.isCloudFetch = true;
      cloudMeta.uuid = uuid;
      cloudMeta.endpointUrl = url;

      const fetchStart = Date.now();
      const resp = await fetch(url, {
        method: 'GET',
        headers: {
          'User-Agent': 'TunnelTweak/2.0 (Android; CloudInspector)',
          Accept: 'application/json',
        },
        cache: 'no-store',
      });
      cloudMeta.httpStatus = resp.status;
      cloudMeta.fetchTimeMs = Date.now() - fetchStart;

      if (resp.status === 404) {
        return NextResponse.json(
          {
            error: `Cloud Configuration "${uuid}" was not found (HTTP 404) or has expired on tunneltweak.com.`,
            cloudMeta,
          },
          { status: 404 }
        );
      }

      if (!resp.ok) {
        return NextResponse.json(
          {
            error: `Cloud server returned HTTP ${resp.status} when fetching ${uuid}.`,
            cloudMeta,
          },
          { status: 502 }
        );
      }

      const cloudJson = await resp.json();
      if (!cloudJson || typeof cloudJson.config !== 'string' || !cloudJson.config.trim()) {
        return NextResponse.json(
          {
            error: 'Cloud response did not contain a valid "config" field.',
            cloudMeta,
          },
          { status: 422 }
        );
      }
      rawEncryptedContent = cloudJson.config.trim();
    }

    // Decrypt / parse payload
    const decryptResult = tryDecryptAny(rawEncryptedContent, passphrase);
    if (!decryptResult.decryptedJson) {
      return NextResponse.json(
        {
          error: decryptResult.error || 'Decryption failed',
          encryptionMethod: decryptResult.encryptionMethod,
          requiresPassphrase: rawEncryptedContent.startsWith(PASSPHRASE_PREFIX),
          cloudMeta,
        },
        { status: 422 }
      );
    }

    const cfg = decryptResult.decryptedJson;

    // Determine active connection type
    const rawType = cfg.tunnelType !== undefined ? Number(cfg.tunnelType) : Number(cfg.type ?? 0);
    const tunnelType = Number.isNaN(rawType) ? 0 : rawType;
    const connTypeInfo = CONNECTION_TYPES[tunnelType] || {
      name: `Custom Mode (${tunnelType})`,
      category: 'SSH' as const,
      badgeColor: 'cyan',
      description: 'Custom tunnel configuration.',
      flowDiagram: ['Client App', 'Custom Tunnel', 'Server'],
    };

    // Expiry check
    const expiryMs = Number(cfg.config_expiry || 0);
    const nowMs = Date.now();
    const isExpired = expiryMs > 0 && nowMs > expiryMs;
    const expiryDateIso = expiryMs > 0 ? new Date(expiryMs).toISOString() : null;
    const remainingHours = expiryMs > 0 ? Math.round(((expiryMs - nowMs) / 3600000) * 10) / 10 : null;

    // Normalize all protocol fields from config (with optional manual probe overrides)
    const isSscContainer = Boolean(cfg.is_ssc_container);
    const sscContainer = cfg.ssc_container || null;
    const isCreebContainer = Boolean(cfg.is_creeb_container);
    const creebContainer = cfg.creeb_container || null;

    // 1. SSH & General
    const sshServer = String(cfg.sshServer || cfg.host || manualServerHost || '').trim();
    const sshPort = String(cfg.sshPort || cfg.port || manualServerPort || '22').trim();
    const sshPortNum = parseInt(sshPort, 10) || 22;
    const sshUser = String(cfg.sshUser || cfg.username || '').trim();
    const sshPass = String(cfg.sshPass || cfg.password || '').trim();
    const sslPort = String(cfg.sslPort || cfg.http_port || manualServerPort || '443').trim();
    const sslPortNum = parseInt(sslPort, 10) || 443;

    // 2. Proxy / Payload / SSL (SNI)
    const proxyHost = String(cfg.proxyHost || cfg.http_host || '').trim();
    const proxyPort = String(cfg.proxyPort || cfg.http_port || '443').trim();
    const proxyPortNum = parseInt(proxyPort, 10) || 443;
    const sni = String(cfg.sni || cfg.sniHost || manualSni || '').trim();
    const payload = String(cfg.message || cfg.payload || '').trim();
    const payloadExpanded = expandHttpPayloadTemplate(payload, sshServer, sshPort, sni);

    // 3. SlowDNS (DNSTT)
    const nameserver = String(cfg.nameserver || cfg.dnsttNameserver || manualNameserver || '').trim();
    const pubkey = String(cfg.pubkey || cfg.dnsttPubkey || '').trim();
    const dnsresolver = String(cfg.dnsresolver || cfg.dnsResolver || '').trim();
    const dnsttRecordType = String(cfg.dnstt_record_type || 'TXT').trim();
    const dnsttWindow = String(cfg.dnstt_window || '0').trim();

    // 4. V2Ray / Xray Core
    const v2rayProtocol = String(cfg.v2ray_protocol || cfg.v2rayProtocol || 'vless').trim().toLowerCase();
    const v2rayServerHost = String(
      cfg.v2ray_server_host || cfg.v2rayServerHost || cfg.v2rayAddress || (tunnelType === 8 || tunnelType === 9 ? sshServer : '')
    ).trim();
    const v2rayServerPort = String(cfg.v2ray_server_port || cfg.v2rayServerPort || cfg.v2rayPort || '443').trim();
    const v2rayPortNum = parseInt(v2rayServerPort, 10) || 443;
    const v2rayUuid = String(cfg.v2ray_uuid || cfg.v2rayUuid || '').trim();
    const v2rayAlterId = String(cfg.v2ray_alter_id || cfg.v2rayAlterId || '0').trim();
    const v2raySecurity = String(cfg.v2ray_security || cfg.v2raySecurity || 'none').trim().toLowerCase();
    const v2rayNetwork = String(cfg.v2ray_network || cfg.v2rayNetwork || 'tcp').trim().toLowerCase();
    const v2raySni = String(cfg.v2ray_sni || cfg.v2raySni || (tunnelType === 8 || tunnelType === 9 ? sni : '')).trim();
    const v2rayWsHost = String(cfg.v2ray_ws_host || cfg.v2rayWsHost || '').trim();
    const v2rayWsPath = String(cfg.v2ray_ws_path || cfg.v2rayWsPath || '/').trim();
    const v2rayPublicKey = String(cfg.v2ray_public_key || cfg.v2rayPublicKey || '').trim();
    const v2rayShortId = String(cfg.v2ray_short_id || cfg.v2rayShortId || '').trim();
    const v2rayAllowInsecure = Boolean(cfg.v2ray_allow_insecure ?? cfg.v2rayAllowInsecure ?? false);
    const v2rayPerformanceMode = Boolean(cfg.v2ray_performance_mode ?? true);
    const v2rayFakeDns = Boolean(cfg.v2ray_fakedns ?? true);
    const v2raySmartRouting = Boolean(cfg.v2ray_smart_routing ?? false);
    const v2rayDomainStrategy = String(cfg.v2ray_domain_strategy || 'AsIs').trim();
    const v2rayRawConfig = String(cfg.v2ray_raw_config || cfg.v2rayConfig || '').trim();

    // 5. Hysteria2
    const hysteriaServer = String(cfg.hysteria_server || cfg.hysteriaServer || (tunnelType === 11 ? sshServer : '')).trim();
    const hysteriaPort = String(cfg.hysteria_port || cfg.hysteriaPort || '443').trim();
    const hysteriaPortNum = parseInt(hysteriaPort, 10) || 443;
    const hysteriaAuth = String(cfg.hysteria_auth || cfg.hysteriaAuth || '').trim();
    const hysteriaSni = String(cfg.hysteria_sni || cfg.hysteriaSni || '').trim();
    const hysteriaInsecure = Boolean(cfg.hysteria_insecure ?? cfg.hysteriaInsecure ?? false);
    const hysteriaObfs = String(cfg.hysteria_obfs || cfg.hysteriaObfs || '').trim();
    const hysteriaUp = String(cfg.hysteria_up || '50').trim();
    const hysteriaDown = String(cfg.hysteria_down || '100').trim();
    const hysteriaPorts = String(cfg.hysteria_ports || '').trim();
    const hysteriaHopInterval = String(cfg.hysteria_hop_interval || '30').trim();

    // 6. WireGuard
    const wireguardRaw = String(cfg.wireguard_config || cfg.wireguardConfig || '').trim();
    const wireguardParsed = parseWireGuardIni(wireguardRaw);

    // 7. Slipstream
    const slipstreamDomain = String(cfg.slipstreamDomain || cfg.slipstream_domain || '').trim();
    const slipstreamCert = String(cfg.slipstreamCert || cfg.slipstream_cert || '').trim();
    const slipstreamDirect = Boolean(cfg.slipstreamDirect ?? cfg.slipstream_direct ?? false);
    const slipSegments = String(cfg.slip_segments || '1').trim();

    // Detect which protocol sections have data present in this configuration
    const hasV2RayData =
      tunnelType === 8 ||
      tunnelType === 9 ||
      Boolean(v2rayServerHost || v2rayUuid || v2rayRawConfig || v2rayWsHost || v2rayPublicKey);
    const hasDnsttData =
      tunnelType === 6 ||
      tunnelType === 8 ||
      tunnelType === 10 ||
      Boolean(nameserver || pubkey);
    const hasProxyPayloadSslData =
      [1, 2, 3, 4, 5, 7].includes(tunnelType) ||
      Boolean(proxyHost || payload || sni);
    const hasHysteriaData =
      tunnelType === 11 ||
      Boolean(hysteriaServer || hysteriaAuth);
    const hasWireGuardData =
      tunnelType === 12 ||
      Boolean(wireguardRaw);
    const hasSlipstreamData =
      tunnelType === 13 ||
      Boolean(slipstreamDomain || slipstreamCert);
    const hasSshData =
      [0, 1, 2, 3, 4, 5, 6, 7].includes(tunnelType) ||
      Boolean(sshServer || sshUser || sshPass);

    // Build V2Ray artifacts if V2Ray fields exist
    const v2rayArtifacts = hasV2RayData
      ? buildV2RayArtifacts({
          protocol: v2rayProtocol,
          serverHost: v2rayServerHost || sshServer,
          serverPort: v2rayServerPort,
          uuid: v2rayUuid,
          alterId: v2rayAlterId,
          security: v2raySecurity,
          network: v2rayNetwork,
          sni: v2raySni,
          wsHost: v2rayWsHost,
          wsPath: v2rayWsPath,
          publicKey: v2rayPublicKey,
          shortId: v2rayShortId,
          allowInsecure: v2rayAllowInsecure,
          domainStrategy: v2rayDomainStrategy,
          remark: cfg.config_message || `TweveTunnel-${v2rayProtocol.toUpperCase()}`,
        })
      : null;

    // Build Hysteria2 URI if Hysteria2 fields exist
    const hysteriaUri = hasHysteriaData && hysteriaServer
      ? `hy2://${encodeURIComponent(hysteriaAuth)}@${hysteriaServer}:${hysteriaPort}/?sni=${encodeURIComponent(
          hysteriaSni || hysteriaServer
        )}&insecure=${hysteriaInsecure ? '1' : '0'}${
          hysteriaObfs ? `&obfs=salamander&obfs-password=${encodeURIComponent(hysteriaObfs)}` : ''
        }${hysteriaPorts ? `&mport=${encodeURIComponent(hysteriaPorts)}` : ''}#${encodeURIComponent(
          cfg.config_message || 'TweveTunnel-Hysteria2'
        )}`
      : null;

    // Build comprehensive validation checks based on active tunnelType AND present fields
    const validationChecks: Array<{
      id: string;
      protocol: string;
      label: string;
      status: 'pass' | 'warn' | 'fail' | 'info';
      value: string;
      detail: string;
    }> = [];

    // Check 1: Expiry
    if (expiryMs === 0) {
      validationChecks.push({
        id: 'expiry',
        protocol: 'General',
        label: 'Config Expiration',
        status: 'pass',
        value: 'No Expiry Set',
        detail: 'Configuration does not have a time-based lock.',
      });
    } else if (isExpired) {
      validationChecks.push({
        id: 'expiry',
        protocol: 'General',
        label: 'Config Expiration',
        status: 'fail',
        value: `EXPIRED (${expiryDateIso})`,
        detail: `Expired ${Math.abs(remainingHours || 0)} hours ago. The app will refuse to start the VPN until renewed.`,
      });
    } else {
      validationChecks.push({
        id: 'expiry',
        protocol: 'General',
        label: 'Config Expiration',
        status: remainingHours !== null && remainingHours < 12 ? 'warn' : 'pass',
        value: `Valid (${remainingHours}h remaining)`,
        detail: `Expires on ${expiryDateIso}.`,
      });
    }

    // Check 2: HWID / Root locks
    if (cfg.hwid_enabled) {
      validationChecks.push({
        id: 'hwid',
        protocol: 'Security',
        label: 'HWID Device Lock',
        status: 'warn',
        value: `Locked (${cfg.hwid_list || 'Empty list'})`,
        detail: 'Only devices matching the allowed Android IDs can use this configuration.',
      });
    }

    // Check 3: SSH Checks (for modes 0..7)
    if (tunnelType <= 7) {
      const sshHostOk = Boolean(sshServer);
      validationChecks.push({
        id: 'ssh_host',
        protocol: 'SSH',
        label: 'SSH Server & Port',
        status: sshHostOk ? 'pass' : 'fail',
        value: sshHostOk ? `${sshServer}:${sshPort}` : 'MISSING',
        detail: sshHostOk
          ? `Target SSH host "${sshServer}" on port ${sshPort}.`
          : 'SSH Server host is empty! Modes 0-7 require an SSH server.',
      });

      const credsOk = Boolean(sshUser && sshPass);
      validationChecks.push({
        id: 'ssh_creds',
        protocol: 'SSH',
        label: 'SSH Authentication (User / Password)',
        status: credsOk ? 'pass' : 'fail',
        value: credsOk ? `${sshUser} / ${'*'.repeat(Math.min(sshPass.length, 8))} (${sshPass.length} chars)` : 'MISSING',
        detail: credsOk
          ? `Username "${sshUser}" and password are present.`
          : 'Missing SSH username or password.',
      });
    }

    // Check 4: Proxy / Payload / SSL (SNI) checks
    if ([4, 5, 7].includes(tunnelType) || proxyHost) {
      const pOk = Boolean(proxyHost);
      validationChecks.push({
        id: 'proxy_endpoint',
        protocol: 'Proxy',
        label: 'HTTP Proxy Host & Port',
        status: pOk ? 'pass' : 'fail',
        value: pOk ? `${proxyHost}:${proxyPort}` : 'MISSING',
        detail: pOk
          ? `Connects via intermediate proxy ${proxyHost}:${proxyPort}.`
          : `Mode "${connTypeInfo.name}" requires a Proxy Host!`,
      });
    }

    if ([1, 3, 5, 7].includes(tunnelType) || payload) {
      const payOk = Boolean(payload);
      validationChecks.push({
        id: 'http_payload',
        protocol: 'Payload',
        label: 'Custom HTTP Payload Injection',
        status: payOk ? 'pass' : 'fail',
        value: payOk ? `${payload.length} chars (${payloadExpanded.detectedTokens.length} dynamic tokens)` : 'MISSING',
        detail: payOk
          ? `Tokens used: ${payloadExpanded.detectedTokens.join(', ') || 'None'}${
              payloadExpanded.splitCount > 0 ? ` | Packet splits: ${payloadExpanded.splitCount}` : ''
            }`
          : `Mode "${connTypeInfo.name}" requires an HTTP Payload string!`,
      });
    }

    if ([2, 3, 7].includes(tunnelType) || sni) {
      const sniOk = Boolean(sni);
      validationChecks.push({
        id: 'tls_sni',
        protocol: 'SSL/TLS',
        label: 'SSL/TLS Bug Host (SNI)',
        status: sniOk ? 'pass' : 'fail',
        value: sniOk ? `${sni} (SSL Port: ${sslPort})` : 'MISSING',
        detail: sniOk
          ? `TLS ClientHello will spoof ServerName "${sni}".`
          : `Mode "${connTypeInfo.name}" requires an SNI Bug Host!`,
      });
    }

    // Check 5: SlowDNS (DNSTT) checks (modes 6, 8, 10 or when present)
    if (hasDnsttData) {
      const isDnsttRequired = [6, 8, 10].includes(tunnelType);
      const nsOk = Boolean(nameserver);
      validationChecks.push({
        id: 'dnstt_ns',
        protocol: 'DNSTT',
        label: 'DNSTT Nameserver Domain',
        status: nsOk ? 'pass' : isDnsttRequired ? 'fail' : 'warn',
        value: nsOk ? `${nameserver} (Record: ${dnsttRecordType})` : 'MISSING',
        detail: nsOk
          ? `Authoritative tunnel domain "${nameserver}" using ${dnsttRecordType} queries.`
          : 'DNSTT Nameserver is required for SlowDNS modes.',
      });

      const cleanPk = pubkey.replace(/\s+/g, '');
      const isHex64 = /^[0-9a-fA-F]{64}$/.test(cleanPk);
      validationChecks.push({
        id: 'dnstt_pk',
        protocol: 'DNSTT',
        label: 'DNSTT Server Public Key (Noise_NK)',
        status: isHex64 ? 'pass' : cleanPk.length > 0 ? 'warn' : isDnsttRequired ? 'fail' : 'info',
        value: cleanPk ? `${cleanPk.slice(0, 16)}... (${cleanPk.length} chars)` : 'MISSING',
        detail: isHex64
          ? 'Valid 64-character hexadecimal Noise_NK Curve25519 public key.'
          : cleanPk
          ? `Key length is ${cleanPk.length} chars (expected 64 hex chars).`
          : 'DNSTT Public Key is missing.',
      });

      validationChecks.push({
        id: 'dnstt_resolver',
        protocol: 'DNSTT',
        label: 'Recursive DNS Resolver (UDP 53)',
        status: dnsresolver ? 'pass' : 'warn',
        value: dnsresolver || 'Not set (Fallback: 8.8.8.8)',
        detail: dnsresolver
          ? `Queries sent to ${dnsresolver}:53.`
          : 'No custom resolver set; app will fallback to dns1 (8.8.8.8).',
      });
    }

    // Check 6: V2Ray / Xray Core checks (modes 8, 9 or when present)
    if (hasV2RayData) {
      const isV2RayRequired = tunnelType === 8 || tunnelType === 9;
      const effectiveV2Host = v2rayServerHost || sshServer;

      // Server Host check (Note: in mode 8 DNSTT+V2Ray, DNSTT provides the transport, while mode 9 connects directly to v2ray_server_host)
      if (tunnelType === 9 || v2rayServerHost) {
        validationChecks.push({
          id: 'v2ray_host',
          protocol: 'V2Ray',
          label: 'V2Ray Server Host & Port',
          status: effectiveV2Host ? 'pass' : 'fail',
          value: effectiveV2Host ? `${effectiveV2Host}:${v2rayServerPort}` : 'MISSING',
          detail: effectiveV2Host
            ? `Outbound ${v2rayProtocol.toUpperCase()} server "${effectiveV2Host}" on port ${v2rayServerPort}.`
            : 'V2Ray Server Host is missing! Mode 9 (V2Ray) cannot connect without a server host.',
        });
      }

      // UUID / Password validation
      const uuidRegexStrict = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
      const isUuidValid =
        v2rayProtocol === 'trojan'
          ? v2rayUuid.length >= 4
          : uuidRegexStrict.test(v2rayUuid);

      validationChecks.push({
        id: 'v2ray_uuid',
        protocol: 'V2Ray',
        label: v2rayProtocol === 'trojan' ? 'Trojan Password / Key' : `V2Ray ${v2rayProtocol.toUpperCase()} UUID`,
        status: isUuidValid ? 'pass' : v2rayUuid ? 'warn' : isV2RayRequired ? 'fail' : 'info',
        value: v2rayUuid || 'MISSING',
        detail: isUuidValid
          ? v2rayProtocol === 'trojan'
            ? `Valid Trojan password (${v2rayUuid.length} chars).`
            : 'Valid RFC-4122 36-character UUID format.'
          : v2rayUuid
          ? `UUID "${v2rayUuid}" does not match standard 8-4-4-4-12 hex UUID format.`
          : 'V2Ray UUID is required for VLESS/VMess/Trojan authentication!',
      });

      // Transport & Security check
      validationChecks.push({
        id: 'v2ray_transport',
        protocol: 'V2Ray',
        label: 'V2Ray Transport & Security Layer',
        status: 'pass',
        value: `Protocol: ${v2rayProtocol.toUpperCase()} | Network: ${v2rayNetwork.toUpperCase()} | Security: ${v2raySecurity.toUpperCase()}`,
        detail:
          v2rayNetwork === 'ws'
            ? `WebSocket Path: "${v2rayWsPath}" | Host Header: "${v2rayWsHost || v2raySni || effectiveV2Host || '(default)'}"`
            : v2rayNetwork === 'grpc'
            ? `gRPC ServiceName: "${v2rayWsPath}"`
            : `Direct ${v2rayNetwork.toUpperCase()} stream with ${v2raySecurity.toUpperCase()} security.`,
      });

      if (v2raySecurity === 'reality') {
        const realityOk = Boolean(v2rayPublicKey);
        validationChecks.push({
          id: 'v2ray_reality',
          protocol: 'V2Ray',
          label: 'Xray REALITY Public Key (pbk) & Short ID (sid)',
          status: realityOk ? 'pass' : 'fail',
          value: realityOk ? `pbk: ${v2rayPublicKey.slice(0, 14)}... | sid: ${v2rayShortId || '(empty)'}` : 'MISSING REALITY PUBLIC KEY',
          detail: realityOk
            ? `REALITY steals TLS certificate from SNI "${v2raySni || '(missing SNI!)'}" authenticated by Public Key.`
            : 'MainActivity.validateConnectionSettings() requires a Reality Public Key when security is set to "reality"!',
        });
      }

      if (v2raySecurity === 'tls' || v2raySecurity === 'reality') {
        const hasV2Sni = Boolean(v2raySni || v2rayWsHost);
        validationChecks.push({
          id: 'v2ray_sni',
          protocol: 'V2Ray',
          label: 'V2Ray TLS / REALITY ServerName (SNI)',
          status: hasV2Sni ? 'pass' : 'warn',
          value: v2raySni || v2rayWsHost || `${effectiveV2Host} (Fallback)`,
          detail: hasV2Sni
            ? `TLS handshake uses ServerName "${v2raySni || v2rayWsHost}"${v2rayAllowInsecure ? ' (allowInsecure=true)' : ''}.`
            : 'No explicit V2Ray SNI configured; Xray will default to the server hostname.',
        });
      }
    }

    // Check 7: Hysteria2 checks (mode 11 or when present)
    if (hasHysteriaData) {
      const hyOk = Boolean(hysteriaServer && hysteriaPort);
      validationChecks.push({
        id: 'hysteria_server',
        protocol: 'Hysteria2',
        label: 'Hysteria2 QUIC Server & Port',
        status: hyOk ? 'pass' : 'fail',
        value: hyOk ? `${hysteriaServer}:${hysteriaPort}${hysteriaPorts ? ` (Hop: ${hysteriaPorts})` : ''}` : 'MISSING',
        detail: hyOk
          ? `Bandwidth profile: Up ${hysteriaUp} Mbps / Down ${hysteriaDown} Mbps | Hop Interval: ${hysteriaHopInterval}s.`
          : 'Hysteria2 requires both Server Host and Port!',
      });

      validationChecks.push({
        id: 'hysteria_auth',
        protocol: 'Hysteria2',
        label: 'Hysteria2 Authentication & Salamander Obfs',
        status: hysteriaAuth ? 'pass' : 'warn',
        value: hysteriaAuth
          ? `Auth: ${hysteriaAuth.slice(0, 10)}... | Obfs: ${hysteriaObfs ? 'Enabled' : 'None'} | SNI: ${hysteriaSni || hysteriaServer}`
          : 'No Auth Password Set',
        detail: hysteriaAuth
          ? `Hysteria2 authentication token present${hysteriaInsecure ? ' (TLS Insecure=true)' : ''}.`
          : 'Hysteria2 auth field is empty.',
      });
    }

    // Check 8: WireGuard checks (mode 12 or when present)
    if (hasWireGuardData) {
      const wgOk = Boolean(
        wireguardParsed &&
          wireguardParsed.interface.validPrivateKey &&
          wireguardParsed.peer.validPublicKey &&
          wireguardParsed.peer.endpointHost
      );
      validationChecks.push({
        id: 'wireguard_config',
        protocol: 'WireGuard',
        label: 'WireGuard [Interface] & [Peer] Profile',
        status: wgOk ? 'pass' : 'fail',
        value: wireguardParsed
          ? `Endpoint: ${wireguardParsed.peer.endpoint || 'MISSING'} | Tunnel IP: ${wireguardParsed.interface.address || 'MISSING'}`
          : 'INVALID INI FORMAT',
        detail: wireguardParsed
          ? `PrivateKey: ${wireguardParsed.interface.validPrivateKey ? 'Valid (44-char Base64)' : 'INVALID'} | Peer PublicKey: ${
              wireguardParsed.peer.validPublicKey ? 'Valid' : 'INVALID'
            } | MTU: ${wireguardParsed.interface.mtu}`
          : 'WireGuard configuration must contain [Interface] and [Peer] sections.',
      });
    }

    // Check 9: Slipstream checks (mode 13 or when present)
    if (hasSlipstreamData) {
      const slipOk = Boolean(slipstreamDomain);
      validationChecks.push({
        id: 'slipstream_domain',
        protocol: 'Slipstream',
        label: 'Slipstream Domain & Segments',
        status: slipOk ? 'pass' : 'fail',
        value: slipOk ? `${slipstreamDomain} (${slipSegments} segments, Direct=${slipstreamDirect})` : 'MISSING',
        detail: slipOk
          ? `Slipstream Cert: ${slipstreamCert ? 'Present' : 'Not set'}`
          : 'Slipstream mode requires a Slipstream Domain.',
      });
    }

    // Check 10: Ssc:// Container Verification Checks
    if (isSscContainer && sscContainer) {
      validationChecks.push({
        id: 'ssc_decryption',
        protocol: 'Ssc://',
        label: 'Ssc:// 3-Layer ChaCha20Legacy-Poly1305 Decryption',
        status: sscContainer.decryptedSuccessfully ? 'pass' : 'warn',
        value: `${sscContainer.profileCount || 1} Profile(s) Decrypted (${sscContainer.byteLength}B / v${sscContainer.outerVersion})`,
        detail: `Outer Title: "${sscContainer.outerAuthorTitle || 'N/A'}" | Note: "${sscContainer.outerBannerNote || 'N/A'}" | Expiry: ${sscContainer.outerExpiryDate}`,
      });
    }

    // Check 11: Creeb Injector (CREEBINJ-<ID>) Cloud Token Verification Checks
    if (isCreebContainer && creebContainer) {
      validationChecks.push({
        id: 'creeb_token_format',
        protocol: 'CREEBINJ',
        label: 'Creeb Injector Cloud Token Framing',
        status: 'pass',
        value: `${creebContainer.fullToken} (ID: ${creebContainer.shortId}, ${creebContainer.idLength} chars)`,
        detail: `Valid CREEBINJ-<ID> cloud reference token format for ${creebContainer.appName}.`,
      });

      validationChecks.push({
        id: 'creeb_resolution_mode',
        protocol: 'CREEBINJ',
        label: 'Cloud Reference Lookup & Live Endpoint Probe',
        status: sshServer || nameserver || sni ? 'pass' : 'info',
        value: sshServer || nameserver || sni
          ? `Probing ${[sshServer && `${sshServer}:${sshPort}`, sni && `SNI:${sni}`, nameserver && `NS:${nameserver}`].filter(Boolean).join(' | ')}`
          : 'Awaiting Cloud API URL or Target Server IP / SNI / Nameserver',
        detail: creebContainer.resolutionNote,
      });
    }

    // ============================================================================
    // LIVE NETWORK DIAGNOSTICS & PROTOCOL HANDSHAKE PROBES
    // ============================================================================
    let networkDiagnostics: any = null;

    if (runNetworkProbes) {
      const effectiveV2Host = v2rayServerHost || (tunnelType === 8 || tunnelType === 9 ? sshServer : '');
      const effectiveTlsTargetHost =
        tunnelType === 9 && effectiveV2Host
          ? effectiveV2Host
          : [4, 5, 7].includes(tunnelType) && proxyHost
          ? proxyHost
          : sshServer || effectiveV2Host || hysteriaServer;
      const effectiveTlsTargetPort =
        tunnelType === 9
          ? v2rayPortNum
          : [4, 5, 7].includes(tunnelType) && proxyHost
          ? proxyPortNum
          : [2, 3].includes(tunnelType)
          ? sslPortNum
          : 443;
      const effectiveSni =
        tunnelType === 8 || tunnelType === 9
          ? v2raySni || v2rayWsHost || sni || effectiveV2Host
          : tunnelType === 11
          ? hysteriaSni || hysteriaServer
          : sni || effectiveTlsTargetHost;

      const shouldProbeTls =
        Boolean(effectiveTlsTargetHost) &&
        ([2, 3, 7, 11].includes(tunnelType) ||
          (hasV2RayData && (v2raySecurity === 'tls' || v2raySecurity === 'reality' || v2rayPortNum === 443)) ||
          Boolean(sni));

      const shouldProbeV2RayWs =
        hasV2RayData &&
        Boolean(effectiveV2Host) &&
        v2rayNetwork === 'ws' &&
        tunnelType !== 8; // In mode 8, WS goes inside DNSTT rather than direct TCP

      const shouldProbeHttpPayload =
        Boolean(payload) &&
        ([1, 3, 5, 7].includes(tunnelType)) &&
        Boolean(proxyHost || sshServer);

      const payloadTargetHost = proxyHost || sshServer;
      const payloadTargetPort = proxyHost ? proxyPortNum : ([2, 3].includes(tunnelType) ? sslPortNum : sshPortNum);
      const payloadUseTls = [3, 7].includes(tunnelType);

      const [
        sshDns,
        nameserverDns,
        proxyDns,
        sniDns,
        v2rayDns,
        hysteriaDns,
        wgEndpointDns,
        sshTcpProbe,
        sslTcpProbe,
        proxyTcpProbe,
        v2rayTcpProbe,
        hysteriaTcpProbe,
        dnsUdpProbe,
        tlsHandshakeProbe,
        v2rayWsUpgradeProbe,
        httpPayloadProbe,
      ] = await Promise.all([
        sshServer ? resolveDomainDetails(sshServer) : Promise.resolve(null),
        nameserver ? resolveDomainDetails(nameserver) : Promise.resolve(null),
        proxyHost ? resolveDomainDetails(proxyHost) : Promise.resolve(null),
        sni ? resolveDomainDetails(sni) : Promise.resolve(null),
        effectiveV2Host && effectiveV2Host !== sshServer ? resolveDomainDetails(effectiveV2Host) : Promise.resolve(null),
        hysteriaServer && hysteriaServer !== sshServer ? resolveDomainDetails(hysteriaServer) : Promise.resolve(null),
        wireguardParsed?.peer.endpointHost ? resolveDomainDetails(wireguardParsed.peer.endpointHost) : Promise.resolve(null),
        sshServer && (tunnelType <= 7 || isSscContainer || isCreebContainer) ? probeTcpPort(sshServer, sshPortNum, 3500) : Promise.resolve(null),
        sshServer && [2, 3].includes(tunnelType) ? probeTcpPort(sshServer, sslPortNum, 3500) : Promise.resolve(null),
        proxyHost ? probeTcpPort(proxyHost, proxyPortNum, 3500) : Promise.resolve(null),
        effectiveV2Host && hasV2RayData ? probeTcpPort(effectiveV2Host, v2rayPortNum, 3800) : Promise.resolve(null),
        hysteriaServer && hasHysteriaData ? probeTcpPort(hysteriaServer, hysteriaPortNum, 3500) : Promise.resolve(null),
        nameserver ? probeDnsOverUdp(dnsresolver || cfg.dns1 || '8.8.8.8', nameserver, 3500) : Promise.resolve(null),
        shouldProbeTls
          ? probeTlsHandshake(effectiveTlsTargetHost, effectiveTlsTargetPort, effectiveSni, 4200)
          : Promise.resolve(null),
        shouldProbeV2RayWs
          ? probeHttpOrWsUpgrade({
              host: effectiveV2Host,
              port: v2rayPortNum,
              useTls: v2raySecurity === 'tls' || v2raySecurity === 'reality' || v2rayPortNum === 443,
              sni: v2raySni || v2rayWsHost || effectiveV2Host,
              wsHost: v2rayWsHost || v2raySni || effectiveV2Host,
              wsPath: v2rayWsPath || '/',
              timeoutMs: 4200,
            })
          : Promise.resolve(null),
        shouldProbeHttpPayload
          ? probeHttpOrWsUpgrade({
              host: payloadTargetHost,
              port: payloadTargetPort,
              useTls: payloadUseTls,
              sni: sni || payloadTargetHost,
              wsHost: sni || payloadTargetHost,
              wsPath: '/',
              customPayload: payloadExpanded.wireRequest,
              timeoutMs: 4200,
            })
          : Promise.resolve(null),
      ]);

      networkDiagnostics = {
        sshDns,
        nameserverDns,
        proxyDns,
        sniDns,
        v2rayDns: v2rayDns || (effectiveV2Host === sshServer ? sshDns : null),
        hysteriaDns: hysteriaDns || (hysteriaServer === sshServer ? sshDns : null),
        wgEndpointDns,
        sshTcpProbe,
        sslTcpProbe,
        proxyTcpProbe,
        v2rayTcpProbe,
        hysteriaTcpProbe,
        dnsUdpProbe,
        tlsHandshakeProbe,
        v2rayWsUpgradeProbe,
        httpPayloadProbe,
      };
    }

    // ============================================================================
    // INTELLIGENT ROOT-CAUSE DIAGNOSIS FOR ALL CONNECTION METHODS
    // ============================================================================
    const rootCauses: string[] = [];
    const recommendations: string[] = [];

    if (isExpired) {
      rootCauses.push(`Configuration expired on ${expiryDateIso}. The app blocks connection startup for expired configs.`);
      recommendations.push('Re-export or re-upload the configuration with a future expiration date.');
    }

    const failedChecks = validationChecks.filter((c) => c.status === 'fail' && c.id !== 'expiry');
    for (const fc of failedChecks) {
      rootCauses.push(`Missing/invalid required ${fc.protocol} parameter: ${fc.label} (${fc.detail})`);
    }

    if (networkDiagnostics) {
      // V2Ray specific diagnostics
      if (tunnelType === 9 || (hasV2RayData && v2rayServerHost)) {
        const v2Dns = networkDiagnostics.v2rayDns;
        if (v2Dns && v2Dns.ipv4?.length === 0) {
          rootCauses.push(`V2Ray Server Host "${v2Dns.domain}" has no DNS A record (NXDOMAIN). Xray cannot resolve the server IP.`);
          recommendations.push(`Verify the domain "${v2Dns.domain}" or replace v2ray_server_host with the server's direct IPv4 address.`);
        }
        if (networkDiagnostics.v2rayTcpProbe && !networkDiagnostics.v2rayTcpProbe.reachable) {
          rootCauses.push(
            `V2Ray TCP port ${v2rayServerHost || sshServer}:${v2rayPortNum} is unreachable (${networkDiagnostics.v2rayTcpProbe.error}).`
          );
          recommendations.push(
            `Check if Xray/V2Ray is running on port ${v2rayPortNum} on the VPS and that firewall (ufw/iptables) allows TCP ${v2rayPortNum}.`
          );
        }
        if (
          (v2raySecurity === 'tls' || v2raySecurity === 'reality') &&
          networkDiagnostics.tlsHandshakeProbe &&
          !networkDiagnostics.tlsHandshakeProbe.success
        ) {
          rootCauses.push(
            `V2Ray TLS/REALITY Handshake to ${v2rayServerHost || sshServer}:${v2rayPortNum} (SNI: ${networkDiagnostics.tlsHandshakeProbe.sniSent}) failed: ${networkDiagnostics.tlsHandshakeProbe.error}.`
          );
          recommendations.push(
            `Check that the TLS certificate or REALITY target on port ${v2rayPortNum} accepts SNI "${networkDiagnostics.tlsHandshakeProbe.sniSent}".`
          );
        }
        if (networkDiagnostics.v2rayWsUpgradeProbe && networkDiagnostics.v2rayWsUpgradeProbe.responded) {
          const wsCode = networkDiagnostics.v2rayWsUpgradeProbe.statusCode;
          if (wsCode === 502 || wsCode === 521 || wsCode === 522 || wsCode === 523 || wsCode === 524) {
            rootCauses.push(
              `CDN / Reverse Proxy returned HTTP ${wsCode} (${networkDiagnostics.v2rayWsUpgradeProbe.statusLine}) during V2Ray WebSocket upgrade! The CDN edge is reachable, but the origin V2Ray backend server is down or blocking Cloudflare IPs.`
            );
            recommendations.push('Restart Xray/V2Ray and Nginx/Caddy on your origin VPS, and verify the origin SSL mode in Cloudflare.');
          } else if (wsCode === 403 || wsCode === 404) {
            rootCauses.push(
              `V2Ray WebSocket Upgrade returned HTTP ${wsCode} (${networkDiagnostics.v2rayWsUpgradeProbe.statusLine}) for path "${v2rayWsPath}" and Host "${v2rayWsHost || v2raySni}".`
            );
            recommendations.push(
              `Verify that your V2Ray server's wsSettings.path matches "${v2rayWsPath}" and Cloudflare Bot Fight Mode is not blocking WebSocket upgrades.`
            );
          }
        }
      }

      // DNSTT specific diagnostics (modes 6, 8, 10)
      if ([6, 8, 10].includes(tunnelType)) {
        if (networkDiagnostics.nameserverDns && networkDiagnostics.nameserverDns.ipv4.length === 0 && networkDiagnostics.nameserverDns.ns.length === 0) {
          rootCauses.push(`DNSTT Nameserver "${nameserver}" failed DNS resolution (no A/NS records).`);
          recommendations.push('Ensure your domain registrar has an A record for the NS host and an NS record delegating the tunnel subdomain to it.');
        }
        if (networkDiagnostics.dnsUdpProbe && !networkDiagnostics.dnsUdpProbe.reachable) {
          rootCauses.push(`DNS Resolver "${dnsresolver || cfg.dns1 || '8.8.8.8'}" did not answer UDP port 53 queries (${networkDiagnostics.dnsUdpProbe.error}).`);
          recommendations.push('Change DNS Resolver to 8.8.8.8, 1.1.1.1, or your local ISP recursive DNS server.');
        } else if (networkDiagnostics.dnsUdpProbe?.rcode === 2) {
          rootCauses.push(
            `DNS Resolver returned RCODE 2 (SERVFAIL) when querying "${nameserver}". This means the authoritative ` +
              `dnstt-server process on your VPS (UDP port 53) is offline or blocked by the VPS firewall!`
          );
          recommendations.push('SSH into your VPS and verify `dnstt-server` is running on UDP port 53 (`ss -ulpn | grep :53`).');
        } else if (networkDiagnostics.dnsUdpProbe?.rcode === 3) {
          rootCauses.push(`DNS Resolver returned RCODE 3 (NXDOMAIN) for "${nameserver}". The tunnel subdomain delegation is missing.`);
        } else if (networkDiagnostics.dnsUdpProbe?.rcode === 5) {
          rootCauses.push(
            `DNS Resolver "${dnsresolver || cfg.dns1 || '8.8.8.8'}" returned RCODE 5 (REFUSED) when querying "${nameserver}" (${networkDiagnostics.dnsUdpProbe.latencyMs}ms). The server is reachable on UDP port 53, but refused the query for "${nameserver}".`
          );
          recommendations.push(
            `Check that dnstt-server on ${dnsresolver || sshServer} is started with the exact domain "${nameserver}", or switch DNS Resolver to 8.8.8.8 / 1.1.1.1 if ${dnsresolver} has recursion disabled.`
          );
        }
      }

      // SSH Direct / SSL / Proxy specific diagnostics (modes 0..5, 7)
      if ([0, 1].includes(tunnelType) && networkDiagnostics.sshTcpProbe && !networkDiagnostics.sshTcpProbe.reachable) {
        rootCauses.push(`SSH Server ${sshServer}:${sshPortNum} is unreachable over TCP (${networkDiagnostics.sshTcpProbe.error}).`);
        recommendations.push('Verify the SSH server IP/domain is online and listening on port ' + sshPortNum + '.');
      }

      if ([2, 3].includes(tunnelType) && networkDiagnostics.tlsHandshakeProbe && !networkDiagnostics.tlsHandshakeProbe.success) {
        rootCauses.push(`SSL/TLS handshake to ${sshServer}:${sslPortNum} with SNI "${sni}" failed (${networkDiagnostics.tlsHandshakeProbe.error}).`);
        recommendations.push(`Check if stunnel/haproxy/xray TLS listener is running on port ${sslPortNum} on ${sshServer}.`);
      }

      if ([4, 5, 7].includes(tunnelType) && networkDiagnostics.proxyTcpProbe && !networkDiagnostics.proxyTcpProbe.reachable) {
        rootCauses.push(`HTTP Proxy ${proxyHost}:${proxyPortNum} is unreachable (${networkDiagnostics.proxyTcpProbe.error}).`);
        recommendations.push(`Verify proxy ${proxyHost}:${proxyPortNum} is online or switch to another working proxy/CDN IP.`);
      }
    }

    if (rootCauses.length === 0) {
      recommendations.push(
        `All configuration fields and live network probes for "${connTypeInfo.name}" passed verification! If a user still cannot connect on mobile data, their carrier may be throttling or blocking the specific SNI/Bug Host or DNS resolver on their SIM plan.`
      );
    }

    return NextResponse.json({
      success: true,
      inspectedAt: new Date().toISOString(),
      cloudMeta,
      encryptionMethod: decryptResult.encryptionMethod,
      summary: {
        configVersion: cfg.config_version ?? 'Unknown',
        configMessage: cfg.config_message || '',
        tunnelType,
        connectionTypeName: connTypeInfo.name,
        connectionCategory: connTypeInfo.category,
        connectionBadgeColor: connTypeInfo.badgeColor,
        connectionTypeDescription: connTypeInfo.description,
        flowDiagram: connTypeInfo.flowDiagram,
        isProtected: Boolean(cfg.config_protected),
        hideSshCredentials: Boolean(cfg.hide_ssh_credentials),
        hideProxySettings: Boolean(cfg.hide_proxy_settings),
        blockRooted: Boolean(cfg.block_rooted),
        hwidEnabled: Boolean(cfg.hwid_enabled),
        hwidList: cfg.hwid_list || '',
        isExpired,
        expiryMs,
        expiryDateIso,
        remainingHours,
        activeProtocolsDetected: [
          ...(isSscContainer ? ['SSH Custom (Ssc://)'] : []),
          ...(isCreebContainer ? ['Creeb Injector (CREEBINJ)'] : []),
          ...(hasSshData ? ['SSH'] : []),
          ...(hasProxyPayloadSslData ? ['Proxy / Payload / SNI'] : []),
          ...(hasDnsttData ? ['SlowDNS (DNSTT)'] : []),
          ...(hasV2RayData ? [`V2Ray (${v2rayProtocol.toUpperCase()})`] : []),
          ...(hasHysteriaData ? ['Hysteria2 (QUIC)'] : []),
          ...(hasWireGuardData ? ['WireGuard'] : []),
          ...(hasSlipstreamData ? ['Slipstream'] : []),
        ],
      },
      connectionDetails: {
        sscContainer: isSscContainer ? sscContainer : null,
        creebContainer: isCreebContainer ? creebContainer : null,
        ssh: {
          present: hasSshData,
          activeInMode: tunnelType <= 7,
          server: sshServer,
          port: sshPort,
          username: sshUser,
          password: sshPass,
          localSocksPort: cfg.sshPortaLocal || cfg.socksPort || '1080',
          compression: Boolean(cfg.ssh_compression),
        },
        proxyAndPayload: {
          present: hasProxyPayloadSslData,
          activeInMode: [1, 2, 3, 4, 5, 7].includes(tunnelType),
          proxyHost,
          proxyPort,
          sni,
          sslPort,
          payload,
          payloadExpandedPreview: payloadExpanded.expandedPreview,
          payloadDetectedTokens: payloadExpanded.detectedTokens,
          payloadSplitCount: payloadExpanded.splitCount,
        },
        slowDns: {
          present: hasDnsttData,
          activeInMode: [6, 8, 10].includes(tunnelType),
          nameserver,
          pubkey,
          dnsResolver: dnsresolver,
          recordType: dnsttRecordType,
          windowSize: dnsttWindow,
        },
        v2ray: {
          present: hasV2RayData,
          activeInMode: tunnelType === 8 || tunnelType === 9,
          protocol: v2rayProtocol,
          serverHost: v2rayServerHost || (tunnelType === 8 || tunnelType === 9 ? sshServer : ''),
          serverPort: v2rayServerPort,
          uuid: v2rayUuid,
          alterId: v2rayAlterId,
          security: v2raySecurity,
          network: v2rayNetwork,
          sni: v2raySni,
          wsHost: v2rayWsHost,
          wsPath: v2rayWsPath,
          publicKey: v2rayPublicKey,
          shortId: v2rayShortId,
          allowInsecure: v2rayAllowInsecure,
          performanceMode: v2rayPerformanceMode,
          fakeDns: v2rayFakeDns,
          smartRouting: v2raySmartRouting,
          domainStrategy: v2rayDomainStrategy,
          hasRawConfig: Boolean(v2rayRawConfig),
          rawConfigPreview: v2rayRawConfig ? v2rayRawConfig.slice(0, 600) : '',
          generatedShareUri: v2rayArtifacts?.shareUri || null,
          generatedXrayOutbound: v2rayArtifacts?.xrayOutbound || null,
        },
        hysteria2: {
          present: hasHysteriaData,
          activeInMode: tunnelType === 11,
          server: hysteriaServer,
          port: hysteriaPort,
          auth: hysteriaAuth,
          sni: hysteriaSni,
          insecure: hysteriaInsecure,
          obfs: hysteriaObfs,
          upMbps: hysteriaUp,
          downMbps: hysteriaDown,
          portHoppingRange: hysteriaPorts,
          hopIntervalSec: hysteriaHopInterval,
          generatedHy2Uri: hysteriaUri,
        },
        wireguard: {
          present: hasWireGuardData,
          activeInMode: tunnelType === 12,
          rawConfig: wireguardRaw,
          parsed: wireguardParsed,
        },
        slipstream: {
          present: hasSlipstreamData,
          activeInMode: tunnelType === 13,
          domain: slipstreamDomain,
          cert: slipstreamCert,
          direct: slipstreamDirect,
          segments: slipSegments,
        },
        networkAndTun: {
          dns1: cfg.dns1 || '8.8.8.8',
          dns2: cfg.dns2 || '8.8.4.4',
          dnsForward: cfg.dnsForward ?? true,
          udpForward: cfg.udpForward ?? true,
          udpResolver: cfg.udpResolver || '127.0.0.1:7300',
          udpgwPort: cfg.udpgwPort || '7300',
          mtu: cfg.mtu || '1500',
          selectedServerId: cfg.selected_server_id || 'custom',
        },
      },
      validationChecks,
      networkDiagnostics,
      diagnosis: {
        healthy: rootCauses.length === 0,
        rootCauses,
        recommendations,
      },
      rawDecryptedConfig: cfg,
    });
  } catch (err: any) {
    return NextResponse.json(
      { error: `Inspector internal error: ${err?.message || 'Unknown error'}` },
      { status: 500 }
    );
  }
}
