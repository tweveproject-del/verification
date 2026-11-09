'use client';

import React, { useState, useRef, useEffect } from 'react';
import { inspectConfigLocally } from './inspector-engine';
import TanzaniaCarrierHub from './components/TanzaniaCarrierHub';
import PlaysmartyCloudHub from './components/PlaysmartyCloudHub';

type ValidationCheck = {
  id: string;
  protocol: string;
  label: string;
  status: 'pass' | 'warn' | 'fail' | 'info';
  value: string;
  detail: string;
};

type InspectResponse = {
  success?: boolean;
  error?: string;
  isPlaysmartyExpired?: boolean;
  rawDecryptedJson?: string;
  rawPayloadBase64?: string;
  downloadFileName?: string;
  requiresPassphrase?: boolean;
  inspectedAt?: string;
  encryptionMethod?: string;
  cloudMeta?: {
    isCloudFetch: boolean;
    uuid: string | null;
    endpointUrl: string | null;
    httpStatus: number | null;
    fetchTimeMs: number | null;
    cloudProvider?: string | null;
    resolvedVia?: string | null;
  };
  summary?: {
    configVersion: number | string;
    configMessage: string;
    tunnelType: number;
    connectionTypeName: string;
    connectionCategory: string;
    connectionBadgeColor: string;
    connectionTypeDescription: string;
    flowDiagram: string[];
    isProtected: boolean;
    hideSshCredentials: boolean;
    hideProxySettings: boolean;
    blockRooted: boolean;
    hwidEnabled: boolean;
    hwidList: string;
    isExpired: boolean;
    expiryMs: number;
    expiryDateIso: string | null;
    remainingHours: number | null;
    activeProtocolsDetected: string[];
  };
  connectionDetails?: {
    sscContainer?: {
      scheme: string;
      appName: string;
      decryptedSuccessfully: boolean;
      usedNestedLockLayer: boolean;
      hexLength: number;
      byteLength: number;
      sha256Fingerprint: string;
      outerAuthorTitle: string;
      outerBannerNote: string;
      outerExpiryDate: string;
      outerVersion: number | string;
      profileCount: number;
      generatedSscUri?: string;
      rawSscFileHex?: string;
      profiles: Array<{
        PROFILE_ID: number | string;
        USER_KEY_NONCE_SEED: string;
        CONFIG_NAME: string;
        TUNNEL_TYPE: string;
        PROTOCOL_ID: number;
        VERSION: number;
        SNI_OR_HOST: string;
        PORT: number;
        SSH_PORT: number;
        USERNAME: string;
        PASSWORD: string;
        UDPGW_PORT: number;
        DNS_RESOLVER: string;
        NS_SERVER: string;
        PUBKEY: string;
        PUBKEY_RAW_HEX?: string;
        PUBKEY_DECRYPTED_SUCCESSFULLY?: boolean;
        PAYLOAD_ENABLED: boolean;
        PAYLOAD: string;
        PROXY_ENABLED: boolean;
        PROXY: string;
        PROXY_PORT: string;
        IS_PREMIUM: boolean;
        IS_DEFAULT: boolean;
        HWID_LOCK: boolean;
        ROOT_LOCK: boolean;
        PLAYSTORE_LOCK: boolean;
        EXPIRY_LOCK: boolean;
        PASSWORD_LOCK: boolean;
      }>;
    } | null;
    creebContainer?: {
      fullToken: string;
      prefix?: string;
      shortId?: string;
      idLength?: number;
      appName: string;
      profileId?: string;
      profileName?: string;
      hostPort?: string;
      serverHost?: string;
      serverPort?: string;
      tunnelType?: number;
      tunnelTypeName?: string;
      sshUser?: string;
      sshPass?: string;
      proxyPayload?: string;
      proxyHost?: string;
      proxyPort?: string;
      slowDnsPubkey?: string;
      udpUp?: string;
      udpDown?: string;
      v2rayJsonRaw?: string;
      v2rayParsed?: {
        add?: string;
        port?: string;
        id?: string;
        aid?: string;
        net?: string;
        path?: string;
        host?: string;
        tls?: string;
        sni?: string;
        ps?: string;
      };
      isLocked?: boolean;
      isImported?: boolean;
      security?: {
        requiresPassword?: boolean;
        passwordHash?: string;
        blockHwid?: boolean;
        hwidString?: string;
        blockedPackages?: string;
        bloquearRoot?: boolean;
        onlyPlayStore?: boolean;
        onlyData?: boolean;
        validade?: number | null;
        validadeFormatted?: string;
      };
      message?: string;
      supportedProtocols?: string[];
      resolutionNote?: string;
      rawBundleJson?: string;
    } | null;
    npvsContainer?: {
      wireFormat: string;
      magic: string;
      version: number;
      headerLength: number;
      headerSubVersion: number;
      ephemeralPublicKey: string;
      payloadFormat: string;
      payloadLength: number;
      signatureR: string;
      signatureS: string;
      cipherSuite: string;
      clientPackage: string;
      profileName: string;
      targetServer: string;
      targetPort: number | string;
      sni: string;
      protocol: string;
      transport: string;
      wsPath: string;
      wsHost: string;
      v2rayUuid: string;
      generatedVlessUri?: string;
      rawEnvelopeHexPreview?: string;
    } | null;
    hcContainer?: {
      wireFormat: string;
      profileName: string;
      clientPackage: string;
      containerType: string;
      fileSize: number;
      charCount: number;
      aesBlocks: number;
      ispTarget: string;
      region: string;
      tunnelMode?: string;
      isV2Ray?: boolean;
      v2rayProtocol?: string;
      sshServer: string;
      sshPort: string;
      sshUser?: string;
      sshPass?: string;
      remoteProxy: string;
      payload: string;
      sni: string;
      slowDnsEnabled: boolean;
      slowDnsPubkey?: string;
      slowDnsNameserver?: string;
      slowDnsResolver?: string;
      containerStatus: string;
      cipherMethod: string;
      isLocked?: boolean;
      matchingPrefixBytes?: number;
      rawHexPreview?: string;
    } | null;
    openTunnelContainer?: {
      wireFormat: string;
      appName: string;
      clientPackage: string;
      appVersionCode: number | string;
      fileName: string;
      fileSize: number;
      configMode: number;
      configModeName: string;
      configMessage: string;
      isProtected: boolean;
      validateApp: boolean;
      lockHost: boolean;
      hwidEnabled: boolean;
      checkRoot: boolean;
      sshServer: string;
      sshPort: string;
      sshUser: string;
      sshPass: string;
      sshPortLocal: string;
      sslHost: string;
      sslProtocol: string;
      proxyRemote: string;
      proxyRemotePort: string;
      proxyPayload: string;
      dnsnameserver: string;
      dnspu: string;
      dnsst: string;
      dnsResolver: string;
      udpResolver: string;
      v2rayConfig: string;
      rawXml: string;
      rawHexPreview?: string;
    } | null;
    isHttpWeakContainer?: boolean;
    httpWeakContainer?: {
      appName: string;
      profileName: string;
      versionName: string;
      tokenOrFile: string;
      wireFormat: string;
      tunnelType: string;
      protocols: {
        openvpn: {
          endpoint: string;
          protocol: string;
          hosts: string[];
          ports: string[];
          preservedPorts: string[];
          nameservers: string[];
          profile: string;
          ovpnConfig: string;
          hasPrivateKeyPassword: boolean;
          privateKeyPassword?: string;
          ovpnPk?: string;
        };
        ssh: {
          endpoint: string;
          hosts: string[];
          ports: string[];
          username: string;
          password?: string;
          ipPortUserPass: string;
          cipherAlias: string;
          cipherAlgorithm: string;
          proxy: {
            type: string;
            hosts: string[];
            ports: string[];
            sni: string;
            payload: string;
          };
        };
        v2ray: {
          profile: string;
          protocol: string;
          v2rayConfig: any;
          serverHost: string;
          serverPort: string;
          uuid: string;
          alterId: string;
          network: string;
          security: string;
          wsPath: string;
          sni: string;
          remarks: string;
          transports: string[];
        };
        hysteria: {
          endpoint: string;
          hosts: string[];
          portSets: string;
          authentication: string;
          obfuscationPassword?: string;
          uploadMbps: number;
          downloadMbps: number;
          receiveWindow: string;
          disableMtuDiscovery: boolean;
          udpIdleTimeoutSeconds: number;
          alpn: string[];
          hopIntervalSeconds: number;
          ca?: string;
        };
        slowdns: {
          nameservers: string[];
          domain: string;
          family: string;
          variant: string;
          encryptionKey: string;
          tlsPorts: string[];
          sslPort: string;
        };
        wireguard: {
          endpoint: string;
          privateKey?: string;
          peerPublicKey: string;
          allowedIps: string;
          dns: string;
          address: string;
        };
      };
      restrictions: {
        requireStoreInstall: boolean;
        blockRoot: boolean;
        mobileOnly: boolean;
        allowedCarrierCodes: string[];
        blockedApps: string[];
        allowReshare: boolean;
        cloudProtected: boolean;
        isCloudPassword: boolean;
        isCloudHwidLock: boolean;
        isCloudUpdateUrl: boolean;
        deviceHwid: string;
        updateUrl: string;
        unlockServer: boolean;
        unlockUserPass: boolean;
        unlockPayload: boolean;
        unlockProxy: boolean;
        unlockAll: boolean;
        expireDate: number | null;
        expireDateFormatted: string;
        isGaming: boolean;
        isTorrent: boolean;
        hideBanner: boolean;
      };
      supportedProtocols: string[];
      rawJson?: string;
    } | null;
    httpInjectorContainer?: {
      wireFormat: string;
      appName: string;
      clientPackage: string;
      appVersion: string;
      fileName: string;
      fileSize: number;
      configName: string;
      configMessage: string;
      tunnelType: string;
      tunnelTypeName: string;
      isProtected: boolean;
      isLocked: boolean;
      lockToDevice: boolean;
      burnAfterImport: boolean;
      isExpired: boolean;
      expiryDate: string | null;
      sshServer: string;
      sshPort: string;
      sshUser: string;
      sshPass: string;
      remoteProxy: string;
      payload: string;
      sni: string;
      slowDnsEnabled: boolean;
      slowDnsNameserver?: string;
      slowDnsPubkey?: string;
      slowDnsResolver?: string;
      v2rayProtocol?: string;
      v2rayServer?: string;
      v2rayPort?: string;
      v2rayUuid?: string;
      v2rayNetwork?: string;
      hysteria2Uri?: string;
      wireguardConfig?: string;
      rawHexPreview?: string;
    } | null;
    isDarkTunnelContainer?: boolean;
    darkTunnelContainer?: {
      appName: string;
      packageName: string;
      profileName: string;
      versionName: string;
      versionCode: number;
      wireFormat: string;
      isClosed: boolean;
      isPasswordProtected: boolean;
      blockRoot: boolean;
      blockPlayStore: boolean;
      isHwidLocked: boolean;
      hwidList: string[];
      expireAt: number | null;
      expireDateFormatted: string;
      isExpired: boolean;
      message: string;
      connectedMessage: string;
      tunnelType: string;
      tunnelTypeName: string;
      protocols: {
        ssh?: {
          host: string;
          port: number;
          username: string;
          password?: string;
        };
        dnstt?: {
          nameserver: string;
          pubkey: string;
          dnsResolver: string;
          dnsPort: number;
        };
        inject?: {
          enabled: boolean;
          mode: string;
          sni: string;
          proxyHost: string;
          proxyPort: number;
          payload: string;
          payloadEnhanced: boolean;
        };
        openvpn?: {
          host: string;
          port: number;
          username: string;
          password?: string;
        };
        v2ray?: {
          protocol: string;
          host: string;
          port: number;
          uuid: string;
          transport: string;
          tls: boolean;
          sni: string;
          wsPath: string;
          wsHost: string;
          grpcServiceName: string;
          mux: boolean;
          customConfigJson?: string;
        };
      };
      cloud: {
        hasCloud: boolean;
        channelUrl: string;
        groupUrl: string;
        cloudEndpoint?: string;
      };
      supportedProtocols: string[];
      rawJson?: string;
    } | null;
    isHaTunnelContainer?: boolean;
    haTunnelContainer?: {
      wireFormat: string;
      magic: string;
      appName: string;
      clientPackage: string;
      profileName: string;
      targetCarrier: string;
      tunnelMode: string;
      tunnelModeId: number;
      serverHost: string;
      serverPort: number;
      sni: string;
      proxyPayload: string;
      proxyRemote: string;
      proxyRemotePort: number;
      blockRoot: boolean;
      blockPlayStore: boolean;
      blockTorrent: boolean;
      hwidLock: boolean;
      isPasswordProtected: boolean;
      expiryDate: string;
      cloudServers: string;
      rawEnvelopeHexPreview: string;
      payloadLength: number;
    } | null;
        isNetmodContainer?: boolean;
    netmodContainer?: {
      appName: string;
      packageName: string;
      versionAndroid?: number;
      isWindowsVer?: boolean;
      wireFormat: string;
      cipher: string;
      keyIndexUsed?: number;
      isUnlockedOrPlain: boolean;
      preventRoot: boolean;
      preventWifi: boolean;
      hwIds: string[];
      expire: string | null;
      isExpired: boolean;
      note: string;
      profileCount: number;
      profiles: Array<{
        id?: number | string;
        remark: string;
        protocol: string;
        hostname: string;
        port: number;
        userId?: string;
        password?: string;
        encryptMethod?: string;
        transferProtocol?: string;
        host?: string;
        path?: string;
        tlsType?: string;
        sni?: string;
        pubKey?: string;
        shortId?: string;
        spiderX?: string;
        fingerprint?: string;
        alpn?: string;
        flow?: string;
        locked?: boolean;
        useMux?: boolean;
        pingResult?: string;
        shareUri?: string;
      }>;
      tunnelConfig?: {
        mode: number;
        modeName: string;
        payload?: string;
        payloadLocked?: boolean;
        sni?: string;
        sniLocked?: boolean;
        proxy?: string;
        proxyLocked?: boolean;
        proxyIndex?: number;
        ssh?: string;
        sshLocked?: boolean;
        sshIndex?: number;
        rr?: string;
        interfaceAddress?: string;
        interfacePrivateKey?: string;
        peerPublicKey?: string;
        peerEndpoint?: string;
        peerPresharedKey?: string;
      };
      serverGroups?: Array<{
        id?: number | string;
        name: string;
        url: string;
        updateTime?: number;
      }>;
      supportedProtocols: string[];
      cloud: {
        hasCloud: boolean;
        subscriptionUrl?: string;
        cloudEndpoint?: string;
      };
      rawDecryptedJson?: string;
    } | null;
    isV2boxContainer?: boolean;
    v2boxContainer?: {
      appName: string;
      packageName: string;
      version: string;
      wireFormat: string;
      magic: string;
      profileName: string;
      isPasswordProtected: boolean;
      isDeviceLocked: boolean;
      allowedDeviceIDs: string[];
      expirationTimestamp: number;
      expirationFormatted: string;
      isExpired: boolean;
      cipher: string;
      keyDerivation: string;
      nonce?: string;
      tag?: string;
      rawEnvelopeHexPreview?: string;
      supportedProtocols: string[];
      activeProtocol: string;
      outboundServer: string;
      outboundPort: number;
      uuid?: string;
      sni?: string;
      transport?: string;
      security?: string;
      path?: string;
      realityPublicKey?: string;
      realityShortId?: string;
      chainingHops?: string[];
      cloud: {
        hasCloud: boolean;
        subscriptionUrl?: string;
        subscriptionRemarks?: string;
        autoUpdate?: boolean;
        updateIntervalHours?: number;
        userInfo?: {
          upload: string;
          download: string;
          total: string;
          expire: string;
        };
        webDavConfig?: {
          enabled: boolean;
          baseUrl: string;
          remoteBasePath: string;
          timeoutSeconds: number;
        };
        apiServer: string;
      };
      ssh?: {
        host: string;
        port: number;
        user: string;
        pass: string;
        udpGwPort: number;
        privateKeyContent?: string;
      };
      hysteria?: {
        hopPorts: string;
        salamander: string;
        pinSha256: string;
        upMbps: number;
        downMbps: number;
      };
      shareLink?: string;
      rawDecryptedText?: string;
    } | null;
    ssh: {
      present: boolean;
      activeInMode: boolean;
      server: string;
      port: string;
      username: string;
      password: string;
      localSocksPort: string;
      compression: boolean;
    };
    proxyAndPayload: {
      present: boolean;
      activeInMode: boolean;
      proxyHost: string;
      proxyPort: string;
      sni: string;
      sslPort: string;
      payload: string;
      payloadExpandedPreview: string;
      payloadDetectedTokens: string[];
      payloadSplitCount: number;
    };
    slowDns: {
      present: boolean;
      activeInMode: boolean;
      nameserver: string;
      pubkey: string;
      dnsResolver: string;
      recordType: string;
      windowSize: string;
    };
    v2ray: {
      present: boolean;
      activeInMode: boolean;
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
      performanceMode: boolean;
      fakeDns: boolean;
      smartRouting: boolean;
      domainStrategy: string;
      hasRawConfig: boolean;
      rawConfigPreview: string;
      generatedShareUri: string | null;
      generatedXrayOutbound: Record<string, any> | null;
    };
    hysteria2: {
      present: boolean;
      activeInMode: boolean;
      server: string;
      port: string;
      auth: string;
      sni: string;
      insecure: boolean;
      obfs: string;
      upMbps: string;
      downMbps: string;
      portHoppingRange: string;
      hopIntervalSec: string;
      generatedHy2Uri: string | null;
    };
    wireguard: {
      present: boolean;
      activeInMode: boolean;
      rawConfig: string;
      parsed: {
        interface: {
          privateKeyMasked: string;
          privateKeyFull: string;
          validPrivateKey: boolean;
          address: string;
          dns: string;
          mtu: string;
        };
        peer: {
          publicKey: string;
          validPublicKey: boolean;
          presharedKeyPresent: boolean;
          endpoint: string;
          endpointHost: string;
          endpointPort: number;
          allowedIPs: string;
          persistentKeepalive: string;
        };
      } | null;
    };
    slipstream: {
      present: boolean;
      activeInMode: boolean;
      domain: string;
      cert: string;
      direct: boolean;
      segments: string;
    };
    networkAndTun: {
      dns1: string;
      dns2: string;
      dnsForward: boolean;
      udpForward: boolean;
      udpResolver: string;
      udpgwPort: string;
      mtu: string;
      selectedServerId: string;
    };
  };
  validationChecks?: ValidationCheck[];
  networkDiagnostics?: any;
  diagnosis?: {
    healthy: boolean;
    rootCauses: string[];
    recommendations: string[];
  };
  rawDecryptedConfig?: Record<string, any>;
};

export default function ConfigInspectorPage() {
  const [input, setInput] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [runNetworkProbes, setRunNetworkProbes] = useState(true);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<InspectResponse | null>(null);
  const [showRawJson, setShowRawJson] = useState(false);
  const [showXrayJson, setShowXrayJson] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [manualServerHost, setManualServerHost] = useState('');
  const [manualServerPort, setManualServerPort] = useState('443');
  const [manualSni, setManualSni] = useState('');
  const [manualNameserver, setManualNameserver] = useState('');
  const [customCloudUrl, setCustomCloudUrl] = useState('');
  const [httpWeakProtocolTab, setHttpWeakProtocolTab] = useState<'openvpn' | 'ssh' | 'v2ray' | 'hysteria' | 'slowdns' | 'wireguard'>('openvpn');
  const [protocolMode, setProtocolMode] = useState<'auto' | 'v2ray' | 'ssh' | 'slowdns'>('auto');
  const [activeProtocolTab, setActiveProtocolTab] = useState<
    'auto' | 'http_injector' | 'opentunnel' | 'hc' | 'npvs' | 'ssc' | 'creeb' | 'httpweak' | 'darktunnel' | 'hatunnel' | 'v2box' | 'netmod' | 'v2ray' | 'dnstt' | 'ssh_proxy' | 'hysteria2' | 'wireguard'
  >('auto');
  const [importedFileInfo, setImportedFileInfo] = useState<{ name: string; size: number } | null>(null);
  const [isDraggingFile, setIsDraggingFile] = useState(false);
  const [showCloudPassword, setShowCloudPassword] = useState(false);
  const [cloudJsonExpanded, setCloudJsonExpanded] = useState(false);
  const [cloudLinkCopied, setCloudLinkCopied] = useState(false);
  const [waybackProbing, setWaybackProbing] = useState(false);
  const [waybackResult, setWaybackResult] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const generatePermanentCloudLink = (content: string): string => {
    if (typeof window === 'undefined') return '';
    try {
      const b64 = btoa(unescape(encodeURIComponent(content)));
      return `${window.location.origin}/#cloud=${encodeURIComponent(b64)}`;
    } catch {
      return `${window.location.origin}/#cloud=${encodeURIComponent(btoa(content))}`;
    }
  };

  const handleCopyCloudLink = (content: string) => {
    const link = generatePermanentCloudLink(content);
    if (navigator.clipboard) {
      navigator.clipboard.writeText(link);
      setCloudLinkCopied(true);
      setTimeout(() => setCloudLinkCopied(false), 3000);
    }
  };

  const handleDownloadHcConfig = () => {
    if (!result?.rawPayloadBase64) return;
    try {
      const byteCharacters = atob(result.rawPayloadBase64);
      const byteNumbers = new Array(byteCharacters.length);
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const blob = new Blob([byteArray], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = result.downloadFileName || 'downloaded_config.hc';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      console.error('Download failed', e);
    }
  };

  const handleProbeWayback = async (targetUrl: string) => {
    setWaybackProbing(true);
    setWaybackResult(null);
    try {
      const wbRes = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(targetUrl)}`);
      if (wbRes.ok) {
        const wbData = await wbRes.json();
        const snap = wbData?.archived_snapshots?.closest?.url;
        if (snap) {
          setWaybackResult(snap);
          handleInspect(snap, 'wayback_recovered.hc');
          return;
        }
      }
      setWaybackResult('no_snapshot');
    } catch {
      setWaybackResult('no_snapshot');
    } finally {
      setWaybackProbing(false);
    }
  };

  const handleInspect = async (
    overrideInput?: string,
    overrideFileNameOrProto?: string,
    overrideProtocol?: 'auto' | 'v2ray' | 'ssh' | 'slowdns'
  ) => {
    const targetInput = overrideInput !== undefined ? overrideInput : input;
    if (!targetInput.trim()) return;

    let effectiveFileName = importedFileInfo?.name || undefined;
    let effectiveProtocol = protocolMode;

    if (overrideFileNameOrProto) {
      if (['auto', 'v2ray', 'ssh', 'slowdns'].includes(overrideFileNameOrProto)) {
        effectiveProtocol = overrideFileNameOrProto as any;
      } else {
        effectiveFileName = overrideFileNameOrProto;
      }
    }
    if (overrideProtocol) {
      effectiveProtocol = overrideProtocol;
    }

    setLoading(true);
    setResult(null);
    try {
      // 1. Try server-side API inspection first if available
      try {
        const res = await fetch('/api/inspect', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            input: targetInput.trim(),
            fileName: effectiveFileName,
            passphrase: passphrase.trim() || undefined,
            runNetworkProbes,
            manualServerHost: manualServerHost.trim() || undefined,
            manualServerPort: manualServerPort.trim() || undefined,
            manualSni: manualSni.trim() || undefined,
            manualNameserver: manualNameserver.trim() || undefined,
            customCloudUrl: customCloudUrl.trim() || undefined,
            protocolMode: effectiveProtocol,
          }),
        });
        if (res.ok) {
          const data: InspectResponse = await res.json();
          setResult(data);
          if (effectiveProtocol === 'v2ray' || (data.connectionDetails?.v2ray?.present && !data.connectionDetails?.ssh?.present)) {
            setActiveProtocolTab('v2ray');
          } else {
            setActiveProtocolTab('auto');
          }
          return;
        }
      } catch {
        // Fallback to client-side engine if /api/inspect is 404 or static
      }

      // 2. Client-side inspection engine (pure browser execution)
      const data = await inspectConfigLocally({
        input: targetInput.trim(),
        fileName: effectiveFileName,
        passphrase: passphrase.trim() || undefined,
        runNetworkProbes,
        manualServerHost: manualServerHost.trim() || undefined,
        manualServerPort: manualServerPort.trim() || undefined,
        manualSni: manualSni.trim() || undefined,
        manualNameserver: manualNameserver.trim() || undefined,
        customCloudUrl: customCloudUrl.trim() || undefined,
        protocolMode: effectiveProtocol,
      });
      setResult(data as InspectResponse);
      if (effectiveProtocol === 'v2ray' || (data.connectionDetails?.v2ray?.present && !data.connectionDetails?.ssh?.present)) {
        setActiveProtocolTab('v2ray');
      } else {
        setActiveProtocolTab('auto');
      }
    } catch (e: any) {
      setResult({ error: e?.message || 'Failed to inspect configuration' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (typeof window !== 'undefined') {
      (window as any).loadConfigFromAndroid = (content: string, fileName?: string) => {
        setInput(content);
        if (fileName) setImportedFileInfo({ name: fileName, size: content.length });
        handleInspect(content, fileName);
      };

      // Auto-load deep cloud links via #cloud=, #cfg= or URL query parameters
      try {
        const hash = window.location.hash;
        if (hash) {
          const cleanHash = hash.replace(/^#/, '');
          const hashParams = new URLSearchParams(cleanHash);
          const cloudHash = hashParams.get('cloud') || hashParams.get('cfg');
          if (cloudHash) {
            let decoded = '';
            try {
              decoded = decodeURIComponent(escape(atob(cloudHash)));
            } catch {
              try {
                decoded = atob(cloudHash);
              } catch {}
            }
            if (decoded) {
              setInput(decoded);
              handleInspect(decoded, 'tweve_cloud_share.conf');
              return;
            }
          }
        }

        const urlParams = new URLSearchParams(window.location.search);
        const cloudParam = urlParams.get('cloud') || urlParams.get('config') || urlParams.get('url');
        if (cloudParam) {
          setInput(cloudParam);
          handleInspect(cloudParam, 'cloud_share');
        }
      } catch {}
    }
  }, []);

  const processImportedFile = (file: File) => {
    setImportedFileInfo({ name: file.name, size: file.size });
    const reader = new FileReader();
    reader.onload = () => {
      const buffer = reader.result;
      if (buffer instanceof ArrayBuffer) {
        const u8 = new Uint8Array(buffer);
        // Check if file starts with NPVS magic (0x4E, 0x50, 0x56, 0x53) or is binary
        const isNpvs = u8.length >= 4 && u8[0] === 0x4e && u8[1] === 0x50 && u8[2] === 0x56 && u8[3] === 0x53;
        const isHc = file.name.toLowerCase().endsWith('.hc') || (u8.length >= 4 && u8[0] === 0xd7 && u8[1] === 0xe4);
        const isTnl = file.name.toLowerCase().endsWith('.tnl') || (u8.length >= 4 && u8[0] === 0x4f && u8[1] === 0x50 && u8[2] === 0x4c && u8[3] === 0x02);
        let isBinary = isNpvs || isHc || isTnl;
        if (!isBinary) {
          for (let i = 0; i < Math.min(u8.length, 512); i++) {
            if (u8[i] === 0) { isBinary = true; break; }
          }
        }
        if (isBinary) {
          let binaryStr = '';
          const chunkSize = 8192;
          for (let i = 0; i < u8.length; i += chunkSize) {
            const chunk = u8.subarray(i, i + chunkSize);
            binaryStr += String.fromCharCode.apply(null, chunk as any);
          }
          const b64 = btoa(binaryStr);
          setInput(b64);
          handleInspect(b64, file.name);
        } else {
          const text = new TextDecoder('utf-8').decode(u8).trim();
          setInput(text);
          handleInspect(text, file.name);
        }
      } else if (typeof buffer === 'string') {
        const cleaned = buffer.trim();
        setInput(cleaned);
        handleInspect(cleaned, file.name);
      }
    };
    reader.readAsArrayBuffer(file);
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    processImportedFile(file);
    e.target.value = '';
  };

  const handleDropFile = (e: React.DragEvent<HTMLElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDraggingFile(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      processImportedFile(file);
    }
  };

  const copyText = (key: string, val: string) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 1800);
  };

  const renderStatusBadge = (status: 'pass' | 'warn' | 'fail' | 'info') => {
    switch (status) {
      case 'pass':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
            PASS
          </span>
        );
      case 'warn':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-400 border border-amber-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            WARN
          </span>
        );
      case 'fail':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-rose-500/15 text-rose-400 border border-rose-500/30">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-ping" />
            FAIL
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-sky-500/15 text-sky-400 border border-sky-500/30">
            INFO
          </span>
        );
    }
  };

  const cd = result?.connectionDetails;
  const sum = result?.summary;
  const diag = result?.networkDiagnostics;

  const showHttpInjectorCard =
    activeProtocolTab === 'http_injector' || (activeProtocolTab === 'auto' && Boolean(cd?.httpInjectorContainer));
  const showOpenTunnelCard =
    activeProtocolTab === 'opentunnel' || (activeProtocolTab === 'auto' && Boolean(cd?.openTunnelContainer));
  const showHcCard =
    activeProtocolTab === 'hc' || (activeProtocolTab === 'auto' && Boolean(cd?.hcContainer));
  const showNpvsCard =
    activeProtocolTab === 'npvs' || (activeProtocolTab === 'auto' && Boolean(cd?.npvsContainer));
  const showSscCard =
    activeProtocolTab === 'ssc' || (activeProtocolTab === 'auto' && Boolean(cd?.sscContainer));
  const showHttpWeakCard =
    activeProtocolTab === 'httpweak' || (activeProtocolTab === 'auto' && Boolean(cd?.httpWeakContainer));
  const showDarkTunnelCard =
    activeProtocolTab === 'darktunnel' || (activeProtocolTab === 'auto' && Boolean(cd?.darkTunnelContainer));
  const showHaTunnelCard =
    activeProtocolTab === 'hatunnel' || (activeProtocolTab === 'auto' && Boolean(cd?.haTunnelContainer));
  const showV2BoxCard =
    activeProtocolTab === 'v2box' || (activeProtocolTab === 'auto' && Boolean(cd?.v2boxContainer));
  const showNetmodCard =
    activeProtocolTab === 'netmod' || (activeProtocolTab === 'auto' && Boolean(cd?.netmodContainer));
  const showCreebCard =
    activeProtocolTab === 'creeb' || (activeProtocolTab === 'auto' && Boolean(cd?.creebContainer));
  const showV2RayCard =
    activeProtocolTab === 'v2ray' || (activeProtocolTab === 'auto' && cd?.v2ray.present);
  const showDnsttCard =
    activeProtocolTab === 'dnstt' || (activeProtocolTab === 'auto' && cd?.slowDns.present);
  const showSshProxyCard =
    activeProtocolTab === 'ssh_proxy' ||
    (activeProtocolTab === 'auto' && (cd?.ssh.present || cd?.proxyAndPayload.present));
  const showHysteriaCard =
    activeProtocolTab === 'hysteria2' || (activeProtocolTab === 'auto' && cd?.hysteria2.present);
  const showWireGuardCard =
    activeProtocolTab === 'wireguard' ||
    (activeProtocolTab === 'auto' && (cd?.wireguard.present || cd?.slipstream.present));

  return (
    <main className="max-w-7xl mx-auto px-2.5 sm:px-6 lg:px-8 py-4 sm:py-8 space-y-4 sm:space-y-6">
      {/* Header */}
      <header className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pb-3.5 border-b border-slate-800/80">
        <div className="flex items-start sm:items-center gap-3">
          <div className="w-10 h-10 sm:w-11 sm:h-11 rounded-xl bg-gradient-to-br from-cyan-400 via-sky-500 to-indigo-600 flex items-center justify-center shadow-lg shadow-cyan-500/25 shrink-0 ring-1 ring-white/20">
            <svg width="22" height="22" className="w-5 h-5 sm:w-6 sm:h-6 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.4}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
            </svg>
          </div>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <h1 className="text-base sm:text-xl font-extrabold tracking-tight text-white">
                Tweve Tunnel <span className="text-gradient-cyan">Inspector</span>
              </h1>
              <span className="px-2.5 py-0.5 text-[10px] sm:text-xs font-bold rounded-full bg-cyan-500/20 text-cyan-200 border border-cyan-400/40 shadow-sm shadow-cyan-500/20 whitespace-nowrap">
                Multi-Protocol • Smart Verification
              </span>
            </div>
            <p className="text-[11px] sm:text-xs text-slate-300 font-medium truncate max-w-xl mt-0.5">
              Decrypt, inspect, and live-verify Cloud UUIDs, VPN config files, and multi-protocol tunnels
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0 w-full sm:w-auto">
          <input
            ref={fileInputRef}
            type="file"
            accept=".twt,.tut,.ssc,.npvs,.npvt,.hc,.tnl,.ehi,.ehil,.creeb,.dark,.dark.backup,.hat,.v2box,.v2b,.json,.txt,.conf"
            onChange={handleFileUpload}
            className="hidden"
            style={{ display: 'none' }}
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="w-full sm:w-auto px-4 py-2.5 sm:py-2 rounded-xl bg-slate-800/90 hover:bg-slate-700/90 text-white text-xs sm:text-sm font-semibold border border-slate-700/80 transition flex items-center justify-center gap-2 cursor-pointer shadow-md active:scale-95"
          >
            <svg width="15" height="15" className="w-4 h-4 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12" />
            </svg>
            <span>Import Config File</span>
            <span className="hidden lg:inline text-[10px] text-cyan-200 font-mono bg-slate-900/90 px-1.5 py-0.5 rounded border border-cyan-500/30 font-bold">.twt / .dark / .v2box / .hat / .npvs</span>
          </button>
        </div>
      </header>

      {/* HTTP Custom (link.playsmarty.uk) Cloud Hub & Live Status Monitor */}
      <PlaysmartyCloudHub
        onLoadAndVerify={(url, proto) => {
          setInput(url);
          if (proto && proto !== 'auto') {
            setProtocolMode(proto);
          }
          handleInspect(url, undefined, proto);
        }}
        onUploadFileClick={() => fileInputRef.current?.click()}
      />

      {/* Tanzania Carrier Presets & Host Line Sync Hub */}
      <TanzaniaCarrierHub
        onLoadConfig={(cfg) => {
          setInput(cfg);
          handleInspect(cfg);
        }}
        onRunInspect={() => handleInspect()}
      />

      {/* Input Section (Supports Drag & Drop for .twt, .tut, .ssc, .npvs, .npvt, .hat, .hc, .tnl, .ehi, .creeb, .dark) */}
      <section
        onDragOver={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setIsDraggingFile(true);
        }}
        onDragLeave={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setIsDraggingFile(false);
        }}
        onDrop={handleDropFile}
        className={`card-modern rounded-2xl p-4 sm:p-5 shadow-2xl transition ${isDraggingFile ? 'border-cyan-400 ring-2 ring-cyan-400/40 bg-cyan-950/30' : ''
          }`}
      >
        {/* Top bar inside card: Label + Format Quick Guide */}
        <div className="flex flex-wrap items-center justify-between gap-2 mb-2.5">
          <label className="text-xs font-bold tracking-wide text-white flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400/80 animate-pulse"></span>
            Config Data, Cloud UUID or Share Link
          </label>
          <span className="text-[11px] font-mono text-cyan-300 font-bold bg-cyan-950/60 px-2 py-0.5 rounded-md border border-cyan-500/30">
            15 VPN Formats Supported
          </span>
        </div>

        {/* List of All Supported VPNs Verified by Web */}
        <div className="mb-3.5 p-3 rounded-xl card-modern-inner">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-2">
            <span className="text-[11px] font-extrabold uppercase tracking-wider text-slate-200 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/80"></span>
              Supported VPN Applications &amp; Verification Modes
            </span>
            <span className="text-[10px] text-slate-300 font-mono hidden sm:inline">
              Drag &amp; Drop file or Paste Cloud ID / Link below
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-2 text-xs">
            {/* HTTP Weak / HTTP Tweak */}
            <div className="p-2 rounded-lg vpn-pill-httpweak transition hover:scale-[1.02]">
              <div className="font-bold text-violet-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-violet-400 shrink-0"></span>
                HTTP Weak / Tweak
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.ht • .hts • config_ • HTTPWEAK-</div>
            </div>

            {/* 1. Tweve Tunnel */}
            <div className="p-2 rounded-lg vpn-pill-tweve transition hover:scale-[1.02]">
              <div className="font-bold text-amber-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0"></span>
                Tweve Tunnel
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.twt • .tut • UUID • Emojis</div>
            </div>

            {/* 2. Creeb Injector */}
            <div className="p-2 rounded-lg vpn-pill-creeb transition hover:scale-[1.02]">
              <div className="font-bold text-emerald-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0"></span>
                Creeb Injector
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.creeb • CREEBINJ-</div>
            </div>

            {/* 3. HTTP Injector */}
            <div className="p-2 rounded-lg vpn-pill-httpinjector transition hover:scale-[1.02]">
              <div className="font-bold text-sky-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400 shrink-0"></span>
                HTTP Injector
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.ehi • .ehil • CgALvYLx</div>
            </div>

            {/* 4. OpenTunnel */}
            <div className="p-2 rounded-lg vpn-pill-opentunnel transition hover:scale-[1.02]">
              <div className="font-bold text-indigo-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 shrink-0"></span>
                OpenTunnel
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.tnl • RoosterKid Cloud</div>
            </div>

            {/* 5. HTTP Custom */}
            <div className="p-2 rounded-lg vpn-pill-httpcustom transition hover:scale-[1.02]">
              <div className="font-bold text-fuchsia-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-fuchsia-400 shrink-0"></span>
                HTTP Custom
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.hc (EasyPro Custom)</div>
            </div>

            {/* 6. NPV Tunnel */}
            <div className="p-2 rounded-lg vpn-pill-napsternetv transition hover:scale-[1.02]">
              <div className="font-bold text-teal-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-teal-400 shrink-0"></span>
                NPV / NapsternetV
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.npvs • .npvt V2/V4</div>
            </div>

            {/* 6b. HA Tunnel Plus */}
            <div className="p-2 rounded-lg vpn-pill-hatunnel transition hover:scale-[1.02]">
              <div className="font-bold text-amber-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400 shrink-0"></span>
                HA Tunnel Plus
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.hat • TNJL Locked Envelope</div>
            </div>

            {/* 6c. V2Box - V2ray Client */}
            <div className="p-2 rounded-lg vpn-pill-v2box transition hover:scale-[1.02]">
              <div className="font-bold text-cyan-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0"></span>
                V2Box Client
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.v2box • v2box:// • chain://</div>
            </div>

            {/* 6d. NetMod Syna */}
            <div className="p-2 rounded-lg vpn-pill-netmod transition hover:scale-[1.02]">
              <div className="font-bold text-sky-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-sky-400 shrink-0"></span>
                NetMod Syna
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.nm • netmod:// • Eichgee AES-256</div>
            </div>

            {/* 7. SSH Custom */}
            <div className="p-2 rounded-lg vpn-pill-sshcustom transition hover:scale-[1.02]">
              <div className="font-bold text-yellow-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 shrink-0"></span>
                SSH Custom
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.ssc • Ssc:// ChaCha20</div>
            </div>

            {/* 8. V2Ray / Xray Core */}
            <div className="p-2 rounded-lg vpn-pill-v2ray transition hover:scale-[1.02]">
              <div className="font-bold text-cyan-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 shrink-0"></span>
                V2Ray / Xray
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">vmess:// • vless:// • trojan://</div>
            </div>

            {/* 9. Hysteria 2 */}
            <div className="p-2 rounded-lg vpn-pill-hysteria2 transition hover:scale-[1.02]">
              <div className="font-bold text-pink-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-pink-400 shrink-0"></span>
                Hysteria 2
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">hy2:// (QUIC / UDP)</div>
            </div>

            {/* 10. WireGuard */}
            <div className="p-2 rounded-lg vpn-pill-wireguard transition hover:scale-[1.02]">
              <div className="font-bold text-orange-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-orange-400 shrink-0"></span>
                WireGuard
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">.conf • Peer &amp; Interface</div>
            </div>

            {/* 11. SlowDNS / DNSTT */}
            <div className="p-2 rounded-lg vpn-pill-slowdns transition hover:scale-[1.02]">
              <div className="font-bold text-blue-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-400 shrink-0"></span>
                SlowDNS (DNSTT)
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">Curve25519 PubKey • NS</div>
            </div>

            {/* 12. Direct Payloads & SSL */}
            <div className="p-2 rounded-lg vpn-pill-sshssl transition hover:scale-[1.02]">
              <div className="font-bold text-emerald-200 text-[11px] truncate flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0"></span>
                SSH / SSL / WS Proxy
              </div>
              <div className="text-[10px] font-mono text-slate-300 mt-0.5 truncate">HTTP [crlf] Payload • SNI</div>
            </div>
          </div>
        </div>

        {importedFileInfo && (
          <div className="mb-3 px-3.5 py-2 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2 text-xs">
              <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-bold uppercase text-[10px]">
                Imported File
              </span>
              <span className="font-mono font-bold text-white truncate max-w-[200px] sm:max-w-none">{importedFileInfo.name}</span>
              <span className="text-slate-400 text-[11px]">({importedFileInfo.size.toLocaleString()} bytes)</span>
            </div>
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="text-xs text-cyan-400 hover:underline cursor-pointer"
            >
              Change File (.twt / .v2box / .creeb / .tut / .ssc / .npvs / .npvt / .hat / .hc / .tnl / .ehi / .dark)
            </button>
          </div>
        )}

        <div className="relative">
          <textarea
            rows={3}
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              if (importedFileInfo) setImportedFileInfo(null);
            }}
            placeholder="Paste Cloud Config UUID, NetMod URI (nm://, netmod://), V2Box URI (v2box://, chain://), CREEBINJ token, Dark Tunnel URI (darktunnel://), share URL (vless://, vmess://, ssc://), or drag & drop a config file (.v2box, .dark, .twt, .creeb, .hc, .npvs, .tnl, .ehi)..."
            className="input-textarea-modern"
          />
        </div>

        {/* Protocol Architecture Quick Selector */}
        <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center gap-1.5 text-xs text-slate-300 font-semibold">
            <span>⚡ Configuration Protocol Architecture:</span>
            <span className="text-[11px] text-slate-400 font-normal">(Xray-Core V2Ray / SSH / SlowDNS)</span>
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {[
              { id: 'auto', label: '🔄 Auto-Detect' },
              { id: 'v2ray', label: '☁️ V2Ray (Xray-Core)' },
              { id: 'ssh', label: '🔐 SSH Tunnel' },
              { id: 'slowdns', label: '📡 SlowDNS (DNSTT)' },
            ].map(p => (
              <button
                key={p.id}
                type="button"
                onClick={() => {
                  setProtocolMode(p.id as any);
                  if (input.trim()) {
                    handleInspect(input, undefined, p.id as any);
                  }
                }}
                className={`px-3 py-1 rounded-lg text-xs font-bold transition cursor-pointer ${
                  protocolMode === p.id
                    ? 'bg-gradient-to-r from-cyan-500 to-indigo-600 text-slate-950 font-black shadow-md shadow-cyan-500/25'
                    : 'bg-slate-950/80 hover:bg-slate-800 text-slate-300 border border-slate-800'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* Options & Action Toolbar */}
        <div className="mt-3.5 pt-3 border-t border-slate-800/80 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
          <div className="flex flex-col sm:flex-row sm:flex-wrap items-stretch sm:items-center gap-2.5 flex-1 min-w-0">
            {/* Inline Passphrase Field */}
            <div className="flex items-center gap-2 bg-slate-950/90 border border-slate-700/80 focus-within:border-cyan-400 focus-within:ring-1 focus-within:ring-cyan-400 rounded-lg px-3 py-2 sm:py-1.5 transition w-full sm:w-auto">
              <svg width="14" height="14" className="w-3.5 h-3.5 text-slate-300 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
              </svg>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Passphrase (optional)"
                className="input-passphrase-modern"
              />
            </div>

            {/* Live Network Probes Toggle Pill */}
            <label className="flex items-center justify-between sm:justify-start gap-2 text-xs text-slate-200 font-semibold cursor-pointer select-none bg-slate-950/90 border border-slate-800 hover:border-slate-700 px-3 py-2 sm:py-1.5 rounded-lg transition shrink-0">
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={runNetworkProbes}
                  onChange={(e) => setRunNetworkProbes(e.target.checked)}
                  className="rounded border-slate-600 text-cyan-500 focus:ring-cyan-500 bg-slate-950 w-4 h-4 cursor-pointer shrink-0"
                />
                <span className="whitespace-nowrap">Live Network Probes</span>
              </div>
            </label>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center gap-2 shrink-0 w-full md:w-auto justify-stretch sm:justify-end flex-wrap">
            {input.trim() && !input.trim().startsWith('http') && (
              <button
                type="button"
                onClick={() => handleCopyCloudLink(input)}
                className="flex-1 sm:flex-none px-3.5 py-2.5 sm:py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs sm:text-sm font-bold border border-emerald-400/40 transition cursor-pointer active:scale-95 text-center flex items-center justify-center gap-1.5 shadow-md shadow-emerald-500/20"
                title="Convert this configuration into a permanent shareable cloud link that never expires"
              >
                <span>{cloudLinkCopied ? '✓ Link Copied!' : '☁️ Share Cloud Link'}</span>
              </button>
            )}
            {(input || result) && (
              <button
                type="button"
                onClick={() => {
                  setInput('');
                  setPassphrase('');
                  setResult(null);
                  setImportedFileInfo(null);
                }}
                className="flex-1 sm:flex-none px-4 py-2.5 sm:py-2 rounded-xl bg-slate-800/90 hover:bg-slate-700 text-slate-200 text-xs sm:text-sm font-bold border border-slate-700 transition cursor-pointer active:scale-95 text-center"
              >
                Clear
              </button>
            )}
            <button
              type="button"
              disabled={loading || !input.trim()}
              onClick={() => handleInspect()}
              className="btn-verify-gradient flex-1 sm:flex-none px-7 py-2.5 sm:py-2 rounded-xl disabled:opacity-40 text-white font-extrabold text-xs sm:text-sm transition flex items-center justify-center gap-2 cursor-pointer active:scale-95 shrink-0"
            >
              {loading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Inspecting...
                </>
              ) : (
                <>
                  <svg width="15" height="15" className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
                  </svg>
                  Verify Config
                </>
              )}
            </button>
          </div>
        </div>
      </section>

      {/* Error Banner */}
      {result?.error && (
        <div className="mt-6 space-y-4">
          <div className="p-5 rounded-2xl bg-rose-950/50 border border-rose-500/40 text-rose-200 flex items-start gap-3.5">
            <svg width="24" height="24" className="w-6 h-6 text-rose-400 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
            <div className="flex-1">
              <h3 className="font-bold text-rose-300">
                {result.isPlaysmartyExpired ? 'HTTP Custom Shortlink Expired / Burned' : 'Configuration Verification Failed'}
              </h3>
              <p className="text-sm mt-1">{result.error}</p>
              {result.encryptionMethod && (
                <p className="text-xs text-rose-300/80 mt-2">
                  Detected Format: <span className="font-mono">{result.encryptionMethod}</span>
                </p>
              )}
            </div>
          </div>

          {result.isPlaysmartyExpired && (
            <div className="p-5 sm:p-6 rounded-2xl bg-gradient-to-r from-amber-950/40 via-slate-900/95 to-amber-950/30 border border-amber-500/40 text-slate-200 space-y-4 shadow-xl">
              <div className="flex items-center gap-2.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse" />
                <h4 className="font-bold text-amber-300 text-sm sm:text-base">
                  HTTP Custom (.hc) Coldplay Shortlink Expired / Burned
                </h4>
              </div>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
                Shortlinks on <code className="text-amber-200 font-mono">link.playsmarty.uk</code> are strictly temporary and automatically self-destruct after <strong className="text-white">30 minutes</strong> or upon the first single-use access (&quot;Opened or expired&quot;). Because this link has already burned, the remote file is no longer available on Coldplay&apos;s server.
              </p>

              {/* Universal New Ways to Verify & Share Cloud Configurations */}
              <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm">⚡</span>
                  <h5 className="text-xs sm:text-sm font-extrabold text-white">
                    New Reliable Ways to Verify &amp; Share Cloud Configurations:
                  </h5>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
                  {/* Way 1: Upload original .hc file */}
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-700/60 flex flex-col justify-between space-y-2">
                    <div>
                      <span className="text-[11px] font-bold text-amber-300 block">1. Direct .hc Upload</span>
                      <p className="text-[11px] text-slate-300 mt-1">Upload the original .hc file from your device to inspect all encrypted parameters offline.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs cursor-pointer shadow transition"
                    >
                      📁 Upload .hc File
                    </button>
                  </div>

                  {/* Way 2: Tweve Permanent Cloud Link */}
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-700/60 flex flex-col justify-between space-y-2">
                    <div>
                      <span className="text-[11px] font-bold text-cyan-300 block">2. Tweve Permanent Cloud</span>
                      <p className="text-[11px] text-slate-300 mt-1">Never burns or expires. Self-contained deep link encodes the payload directly into the URL.</p>
                    </div>
                    <button
                      type="button"
                      onClick={() => {
                        if (input && !input.startsWith('http')) {
                          handleCopyCloudLink(input);
                        } else {
                          fileInputRef.current?.click();
                        }
                      }}
                      className="px-3 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs cursor-pointer shadow transition"
                    >
                      {cloudLinkCopied ? '✓ Link Copied!' : '⚡ Create Permanent Link'}
                    </button>
                  </div>

                  {/* Way 3: Web Archive Recovery Probe */}
                  <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-700/60 flex flex-col justify-between space-y-2">
                    <div>
                      <span className="text-[11px] font-bold text-emerald-300 block">3. Web Archive Snapshot</span>
                      <p className="text-[11px] text-slate-300 mt-1">Check if Wayback Machine cached the shortlink before it expired.</p>
                    </div>
                    <button
                      type="button"
                      disabled={waybackProbing}
                      onClick={() => handleProbeWayback(input.trim())}
                      className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold text-xs cursor-pointer shadow transition flex items-center justify-center gap-1.5"
                    >
                      {waybackProbing ? (
                        <>
                          <span className="w-3 h-3 border-2 border-white border-t-transparent rounded-full animate-spin" />
                          Checking...
                        </>
                      ) : (
                        '🔍 Probe Wayback Cache'
                      )}
                    </button>
                  </div>
                </div>

                {waybackResult === 'no_snapshot' && (
                  <p className="text-[11px] text-rose-300 bg-rose-950/40 p-2 rounded border border-rose-800/40">
                    No Wayback Machine snapshot found for this temporary link. Please upload the .hc file directly or use a permanent cloud host.
                  </p>
                )}

                {/* Supported Permanent Hosts Guidance */}
                <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-2 text-[11px] text-slate-300">
                  <span className="font-semibold text-white">Supported Permanent Cloud Hosts:</span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">Google Drive (direct)</span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">Dropbox (dl=1)</span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">GitHub Gist (raw)</span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">Pastebin (raw)</span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">Rentry.co (raw)</span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 font-mono">OpenTunnel Cloud UUID</span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Results Dashboard */}
      {result?.success && sum && cd && (
        <div className="mt-6 space-y-6">
          {/* 1. Active Connection Method & Flow Pipeline Banner */}
          <div className="p-5 rounded-2xl card-modern shadow-xl">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div>
                <div className="flex items-center gap-2.5 flex-wrap">
                  <span className="px-3 py-1 rounded-lg text-xs font-extrabold uppercase tracking-wider bg-cyan-500/25 text-cyan-200 border border-cyan-400/50 shadow-sm shadow-cyan-500/25">
                    Mode #{sum.tunnelType} • {sum.connectionCategory}
                  </span>
                  <h2 className="text-xl font-extrabold text-white tracking-tight">{sum.connectionTypeName}</h2>
                  {sum.isProtected && (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-amber-500/20 text-amber-300 border border-amber-400/40 shadow-sm shadow-amber-500/20">
                      Locked / Protected Config
                    </span>
                  )}
                </div>
                <p className="text-sm text-slate-200 font-medium mt-1.5">{sum.connectionTypeDescription}</p>
              </div>

              {/* Detected Protocol Badges */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-xs text-slate-300 font-semibold mr-1">Configured Blocks:</span>
                {sum.activeProtocolsDetected.map((proto) => (
                  <span
                    key={proto}
                    className="px-2.5 py-1 rounded-lg text-xs font-bold bg-emerald-500/20 text-emerald-200 border border-emerald-400/40 shadow-sm shadow-emerald-500/20"
                  >
                    {proto}
                  </span>
                ))}
              </div>
            </div>

            {/* Visual Connection Flow Pipeline */}
            {sum.flowDiagram && sum.flowDiagram.length > 0 && (
              <div className="mt-4 pt-4 border-t border-slate-700/80 flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-300 mr-1">
                  Tunnel Packet Path:
                </span>
                {sum.flowDiagram.map((step, idx) => (
                  <React.Fragment key={idx}>
                    <div className="px-3 py-1.5 rounded-xl card-modern-inner text-xs font-mono font-bold text-white flex items-center gap-1.5 border border-slate-700 shadow-sm">
                      <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400/80" />
                      {step}
                    </div>
                    {idx < sum.flowDiagram.length - 1 && (
                      <svg width="16" height="16" className="w-4 h-4 text-cyan-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                      </svg>
                    )}
                  </React.Fragment>
                ))}
              </div>
            )}
          </div>

          {/* 2. Root-Cause Diagnosis Banner */}
          {result.diagnosis && (
            <div
              className={`p-5 rounded-2xl border ${result.diagnosis.healthy
                ? 'bg-emerald-950/30 border-emerald-500/40 text-emerald-100'
                : 'bg-amber-950/35 border-amber-500/40 text-amber-100'
                }`}
            >
              <div className="flex items-start gap-3.5">
                <div
                  className={`w-10 h-10 rounded-xl flex items-center justify-center shrink-0 ${result.diagnosis.healthy
                    ? 'bg-emerald-500/20 text-emerald-400'
                    : 'bg-amber-500/20 text-amber-400'
                    }`}
                >
                  {result.diagnosis.healthy ? (
                    <svg width="24" height="24" className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                  ) : (
                    <svg width="24" height="24" className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                  )}
                </div>

                <div className="flex-1">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="text-base font-bold">
                      {result.diagnosis.healthy
                        ? `Verification Passed — ${sum.connectionTypeName} Is Properly Configured & Reachable`
                        : `Connection Failure Diagnosis (${result.diagnosis.rootCauses.length} Issue${result.diagnosis.rootCauses.length > 1 ? 's' : ''
                        } Detected)`}
                    </h2>
                    <span className="text-xs font-mono opacity-75">{result.encryptionMethod}</span>
                  </div>

                  {result.diagnosis.rootCauses.length > 0 && (
                    <div className="mt-3 space-y-1.5">
                      <p className="text-xs font-semibold uppercase tracking-wider text-rose-300">
                        Why the VPN Fails to Connect:
                      </p>
                      <ul className="list-disc list-inside text-sm space-y-1 text-amber-100/95">
                        {result.diagnosis.rootCauses.map((rc, idx) => (
                          <li key={idx}>{rc}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {result.diagnosis.recommendations.length > 0 && (
                    <div className="mt-3 space-y-1">
                      <p className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                        Recommended Action:
                      </p>
                      <ul className="list-disc list-inside text-sm space-y-1 text-slate-200">
                        {result.diagnosis.recommendations.map((rec, idx) => (
                          <li key={idx}>{rec}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 3. Top Summary KPI Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Active Connection Mode
              </span>
              <div className="mt-1.5 flex items-baseline gap-2">
                <span className="text-lg font-bold text-cyan-400">{sum.connectionTypeName}</span>
                <span className="text-xs font-mono text-slate-500">(#{sum.tunnelType})</span>
              </div>
              <p className="text-xs text-slate-400 mt-1 line-clamp-2">{sum.connectionTypeDescription}</p>
            </div>

            <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Expiration Status
              </span>
              <div className="mt-1.5">
                {sum.expiryMs === 0 ? (
                  <span className="text-lg font-bold text-emerald-400">Unlimited (No Expiry)</span>
                ) : sum.isExpired ? (
                  <span className="text-lg font-bold text-rose-400">EXPIRED</span>
                ) : (
                  <span className="text-lg font-bold text-emerald-400">{sum.remainingHours}h Remaining</span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                {sum.expiryDateIso ? new Date(sum.expiryDateIso).toLocaleString() : 'Never expires'}
              </p>
            </div>

            <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Protection & Locks
              </span>
              <div className="mt-1.5 flex flex-wrap gap-1.5">
                <span
                  className={`px-2 py-0.5 rounded text-xs font-semibold ${sum.isProtected ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-300'
                    }`}
                >
                  {sum.isProtected ? 'Protected' : 'Unlocked'}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-xs font-semibold ${sum.blockRooted ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-400'
                    }`}
                >
                  {sum.blockRooted ? 'Blocks Root' : 'Root Allowed'}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-xs font-semibold ${sum.hwidEnabled ? 'bg-purple-500/20 text-purple-300' : 'bg-slate-800 text-slate-400'
                    }`}
                >
                  {sum.hwidEnabled ? 'HWID Locked' : 'Any Device'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Config Version: <span className="font-mono text-slate-200">v{sum.configVersion}</span>
              </p>
            </div>

            <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Source / Cloud Status
              </span>
              <div className="mt-1.5">
                {result.cloudMeta?.isCloudFetch ? (
                  <div className="flex items-center gap-2">
                    <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="text-lg font-bold text-white">
                      HTTP {result.cloudMeta.httpStatus} ({result.cloudMeta.fetchTimeMs}ms)
                    </span>
                  </div>
                ) : (
                  <span className="text-lg font-bold text-sky-400">Direct Payload / File</span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono truncate">
                {result.cloudMeta?.cloudProvider
                  ? `${result.cloudMeta.cloudProvider} (${result.cloudMeta.uuid})`
                  : result.cloudMeta?.uuid || result.encryptionMethod}
              </p>
            </div>
          </div>

          {/* Cloud Verification & Origin Banner */}
          {result.cloudMeta?.isCloudFetch && (
            <div className="space-y-4">
              <div className="bg-gradient-to-r from-cyan-950/40 via-slate-900/90 to-teal-950/40 border border-cyan-500/40 rounded-2xl p-4 sm:p-5 shadow-xl space-y-3">
                <div className="flex items-center justify-between border-b border-cyan-500/20 pb-3 flex-wrap gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="w-3 h-3 rounded-full bg-cyan-400 shadow-sm shadow-cyan-400 animate-pulse" />
                    <h3 className="text-sm sm:text-base font-bold text-white">
                      Cloud Configuration Verified — <span className="text-cyan-300 font-mono break-all">{result.cloudMeta.uuid}</span>
                    </h3>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30">
                      HTTP {result.cloudMeta.httpStatus} OK • {result.cloudMeta.fetchTimeMs}ms
                    </span>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                      {result.cloudMeta.cloudProvider || 'TunnelTweak Cloud'}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-slate-400 font-medium uppercase tracking-wider text-[11px] block">
                      Cloud Source / UUID
                    </span>
                    <div className="flex items-center justify-between gap-2 mt-1">
                      <span className="font-mono text-cyan-200 font-bold truncate">
                        {result.cloudMeta.uuid}
                      </span>
                      <button
                        type="button"
                        onClick={() => copyText('cloudUuid', result.cloudMeta?.uuid || '')}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 shrink-0 cursor-pointer text-[11px]"
                      >
                        {copiedKey === 'cloudUuid' ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-slate-400 font-medium uppercase tracking-wider text-[11px] block">
                      Cloud API Endpoint
                    </span>
                    <div className="flex items-center justify-between gap-2 mt-1">
                      <a
                        href={result.cloudMeta.endpointUrl || '#'}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="font-mono text-cyan-400 hover:underline truncate"
                        title={result.cloudMeta.endpointUrl || ''}
                      >
                        {result.cloudMeta.endpointUrl}
                      </a>
                      <button
                        type="button"
                        onClick={() => copyText('cloudUrl', result.cloudMeta?.endpointUrl || '')}
                        className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 shrink-0 cursor-pointer text-[11px]"
                      >
                        {copiedKey === 'cloudUrl' ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-slate-400 font-medium uppercase tracking-wider text-[11px] block">
                      Resolution Channel
                    </span>
                    <span className="font-semibold text-slate-200 mt-1 block">
                      {result.cloudMeta.resolvedVia || 'TunnelTweak Direct'}
                    </span>
                  </div>

                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                    <span className="text-slate-400 font-medium uppercase tracking-wider text-[11px] block">
                      Payload Decryption
                    </span>
                    <span className="font-semibold text-emerald-300 mt-1 block truncate">
                      {result.encryptionMethod || 'AES-128-CBC Decrypted'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Real Actual Configuration of Cloud Config Showcase Card */}
              <div className="bg-gradient-to-b from-slate-900/95 via-slate-950 to-slate-900/95 border-2 border-cyan-500/50 rounded-2xl p-4 sm:p-6 shadow-2xl space-y-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-4 border-b border-cyan-500/30 gap-3">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center shrink-0">
                      <span className="text-xl">☁️</span>
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h3 className="text-base sm:text-lg font-black text-white">
                          Real Actual Configuration of Cloud Config
                        </h3>
                        <span className="px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                          100% Offline Decrypted
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Provider: <span className="text-cyan-300 font-mono">{result.cloudMeta.cloudProvider || 'TunnelTweak Cloud API'}</span> • Mode #{sum.tunnelType} ({sum.connectionTypeName})
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    {result.rawPayloadBase64 && (
                      <button
                        type="button"
                        onClick={handleDownloadHcConfig}
                        className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-bold transition cursor-pointer border border-cyan-500/30 flex items-center gap-1.5 shadow"
                        title="Download the captured .hc configuration file to your computer or phone so you can import it into HTTP Custom app"
                      >
                        <span>💾</span> Download .hc Config
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => handleCopyCloudLink(result.rawDecryptedJson || input)}
                      className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 text-xs font-black transition cursor-pointer shadow-md shadow-emerald-500/20 flex items-center gap-1.5"
                      title="Generate a self-contained permanent cloud link that never burns or expires"
                    >
                      <span>{cloudLinkCopied ? '✓ Copied Permanent Cloud Link!' : '⚡ Share Permanent Cloud Link'}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => copyText('allCloudConfig', result.rawDecryptedJson || JSON.stringify(result.rawDecryptedConfig || cd, null, 2))}
                      className="px-3.5 py-1.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-black transition cursor-pointer shadow-md shadow-cyan-500/20 flex items-center gap-1.5"
                    >
                      <span>{copiedKey === 'allCloudConfig' ? '✓ Copied Real Config!' : '📋 Copy Real Config'}</span>
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5 text-xs">
                  {/* 1. Protocol & Tunnel Mode */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">
                      Decrypted Tunnel Protocol
                    </span>
                    <div className="text-sm font-extrabold text-white flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-cyan-400" />
                      <span>{sum.connectionTypeName}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono">
                      Category: {sum.connectionCategory} • TunnelType #{sum.tunnelType}
                    </div>
                  </div>

                  {/* 2. Remote Server Endpoint */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">
                      Remote Server &amp; Port
                    </span>
                    <div className="flex items-center justify-between gap-2">
                      {cd.hcContainer?.isLocked ? (
                        <span className="font-mono text-amber-300 font-bold text-xs truncate flex items-center gap-1">
                          🔒 Encrypted in Container (App Outbound)
                        </span>
                      ) : (
                        <span className="font-mono text-cyan-200 font-bold text-xs truncate">
                          {cd.ssh.server || cd.v2ray.serverHost || cd.hysteria2.server || 'Dynamic / Gateway'} : {cd.ssh.port || cd.v2ray.serverPort || cd.hysteria2.port || '443'}
                        </span>
                      )}
                      {!cd.hcContainer?.isLocked && (cd.ssh.server || cd.v2ray.serverHost) && (
                        <button
                          type="button"
                          onClick={() => copyText('cloudServer', `${cd.ssh.server || cd.v2ray.serverHost}:${cd.ssh.port || cd.v2ray.serverPort}`)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[10px] font-mono cursor-pointer"
                        >
                          {copiedKey === 'cloudServer' ? 'Copied!' : 'Copy'}
                        </button>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      {cd.hcContainer?.isLocked ? (
                        <span>Core: <span className="font-mono text-cyan-300">libaio.so (dev/epro/xray)</span></span>
                      ) : (
                        <span>Proxy: <span className="font-mono text-slate-300">{cd.proxyAndPayload.proxyHost ? `${cd.proxyAndPayload.proxyHost}:${cd.proxyAndPayload.proxyPort}` : 'Direct Connection'}</span></span>
                      )}
                    </div>
                  </div>

                  {/* 3. SNI / SSL Spoofer */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">
                      SNI / TLS Spoofer
                    </span>
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-emerald-300 font-bold text-xs truncate">
                        {cd.proxyAndPayload.sni || cd.v2ray.sni || cd.hysteria2.sni || (cd.hcContainer?.isLocked ? '🔒 Protected (TLS Handshake)' : 'None / Plain TCP')}
                      </span>
                      {(cd.proxyAndPayload.sni || cd.v2ray.sni) && (
                        <button
                          type="button"
                          onClick={() => copyText('cloudSni', cd.proxyAndPayload.sni || cd.v2ray.sni)}
                          className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-emerald-300 text-[10px] font-mono cursor-pointer"
                        >
                          {copiedKey === 'cloudSni' ? 'Copied!' : 'Copy'}
                        </button>
                      )}
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Port: <span className="font-mono text-slate-300">{cd.proxyAndPayload.sslPort || '443'}</span> • SSL / SNI Spoof
                    </div>
                  </div>

                  {/* 4. Credentials */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">
                      Authentication Credentials
                    </span>
                    {cd.hcContainer?.isLocked ? (
                      <div className="font-mono text-[11px] space-y-1">
                        <div className="text-amber-300 font-bold flex items-center gap-1">
                          🔒 Injected into Xray Core
                        </div>
                        <div className="text-slate-400 text-[10px]">
                          State: <span className="text-emerald-400 font-semibold">Active Protected Profile</span>
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="flex items-center justify-between font-mono text-[11px]">
                          <span className="text-slate-400">User:</span>
                          <span className="text-cyan-300 font-bold">{cd.ssh.username || (cd.v2ray.uuid ? `UUID: ${cd.v2ray.uuid.slice(0, 8)}...` : 'Pre-configured')}</span>
                        </div>
                        <div className="flex items-center justify-between font-mono text-[11px]">
                          <span className="text-slate-400">Password:</span>
                          <div className="flex items-center gap-1.5">
                            <span className="text-amber-300 font-bold">
                              {showCloudPassword ? (cd.ssh.password || 'none') : (cd.ssh.password ? '••••••••' : 'none')}
                            </span>
                            {cd.ssh.password && (
                              <button
                                type="button"
                                onClick={() => setShowCloudPassword(!showCloudPassword)}
                                className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 cursor-pointer"
                              >
                                {showCloudPassword ? 'Hide' : 'Show'}
                              </button>
                            )}
                          </div>
                        </div>
                      </>
                    )}
                  </div>

                  {/* 5. Device Lock & Hardware ID */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">
                      Device &amp; Hardware ID Lock
                    </span>
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${sum.hwidEnabled ? 'bg-amber-400' : 'bg-emerald-400'}`} />
                      <span className="font-extrabold text-white text-xs">
                        {sum.hwidEnabled ? 'HWID Device Locked' : 'Unlocked (Any Device)'}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono truncate">
                      {sum.hwidEnabled ? `Allowed HWID: ${sum.hwidList || 'Enforced'}` : 'Universal Device Compatibility'}
                    </div>
                  </div>

                  {/* 6. Expiry & Root Security */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] block">
                      Expiration &amp; Root Check
                    </span>
                    <div className="flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${sum.isExpired ? 'bg-rose-400' : 'bg-emerald-400'}`} />
                      <span className={`font-extrabold text-xs ${sum.isExpired ? 'text-rose-300' : 'text-emerald-300'}`}>
                        {sum.isExpired ? 'Expired' : (sum.expiryDateIso ? `Active (${sum.remainingHours}h remaining)` : 'Lifetime / No Expiry')}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400">
                      Root: <span className={sum.blockRooted ? 'text-amber-300 font-semibold' : 'text-slate-300'}>{sum.blockRooted ? 'Blocked on Rooted Phones' : 'Allowed on All Phones'}</span>
                    </div>
                  </div>
                </div>

                {/* Injected HTTP Payload Box */}
                {cd.proxyAndPayload.payload && (
                  <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px] flex items-center gap-2">
                        <span>Injected HTTP Payload</span>
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/20 text-cyan-300 font-mono">
                          {cd.proxyAndPayload.payloadDetectedTokens?.length || 0} Dynamic Tokens
                        </span>
                      </span>
                      <button
                        type="button"
                        onClick={() => copyText('cloudPayload', cd.proxyAndPayload.payload)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-mono cursor-pointer"
                      >
                        {copiedKey === 'cloudPayload' ? 'Copied!' : 'Copy Payload'}
                      </button>
                    </div>
                    <pre className="p-3 rounded-lg bg-[#020617] border border-slate-800/80 text-[11px] font-mono text-cyan-200 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                      {cd.proxyAndPayload.payload}
                    </pre>
                    {cd.proxyAndPayload.payloadExpandedPreview && (
                      <div className="pt-1.5">
                        <span className="text-slate-500 text-[10px] block mb-1">Live Expanded Request to Gateway:</span>
                        <pre className="p-2.5 rounded bg-[#030712] border border-slate-900 text-[10px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap break-all">
                          {cd.proxyAndPayload.payloadExpandedPreview}
                        </pre>
                      </div>
                    )}
                  </div>
                )}

                {/* Decrypted Configuration JSON Dump Viewer */}
                <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-slate-400 font-bold uppercase tracking-wider text-[10px]">
                        Decrypted Configuration Object (Full Dump)
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setCloudJsonExpanded(!cloudJsonExpanded)}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] cursor-pointer"
                      >
                        {cloudJsonExpanded ? '▲ Collapse JSON' : '▼ Expand Complete JSON'}
                      </button>
                      <button
                        type="button"
                        onClick={() => copyText('cloudDecryptedJson', result.rawDecryptedJson || JSON.stringify(result.rawDecryptedConfig || cd, null, 2))}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 text-[11px] font-mono cursor-pointer"
                      >
                        {copiedKey === 'cloudDecryptedJson' ? 'Copied!' : 'Copy JSON'}
                      </button>
                    </div>
                  </div>
                  {cloudJsonExpanded ? (
                    <pre className="p-3 rounded-lg bg-[#020617] border border-slate-800 text-[11px] font-mono text-slate-200 overflow-x-auto max-h-[450px]">
                      {result.rawDecryptedJson || JSON.stringify(result.rawDecryptedConfig || cd, null, 2)}
                    </pre>
                  ) : (
                    <div
                      onClick={() => setCloudJsonExpanded(true)}
                      className="p-3 rounded-lg bg-[#020617] border border-slate-800/80 text-[11px] font-mono text-slate-400 cursor-pointer hover:border-cyan-500/50 transition flex items-center justify-between"
                    >
                      <span>Click to inspect full decrypted JSON configuration parameters...</span>
                      <span className="text-cyan-400 font-bold">Show JSON &gt;</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Config Message / Note */}
          {sum.configMessage && (
            <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4 sm:p-5 space-y-2">
              <div className="flex items-center justify-between">
                <span className="px-2.5 py-1 rounded-lg bg-cyan-500/15 text-cyan-300 text-xs font-bold uppercase tracking-wider">
                  Config Announcement & Notes
                </span>
                <span className="text-xs text-slate-400">TunnelTweak Broadcaster</span>
              </div>
              <p className="text-sm text-slate-200 font-medium whitespace-pre-line leading-relaxed font-sans bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
                {sum.configMessage}
              </p>
            </div>
          )}

          {/* 4. Protocol Inspector Tab Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-1.5 sm:gap-2 overflow-x-auto no-scrollbar pb-1.5 max-w-full -mx-1 px-1 sm:mx-0 sm:px-0 sm:flex-wrap">
              {[
                { id: 'auto', label: 'Active & Populated Protocols', count: sum.activeProtocolsDetected.length },
                ...(cd.httpInjectorContainer ? [{ id: 'http_injector', label: 'HTTP Injector (.ehi)', active: true }] : []),
                ...(cd.openTunnelContainer ? [{ id: 'opentunnel', label: 'OpenTunnel (.tnl)', active: true }] : []),
                ...(cd.hcContainer ? [{ id: 'hc', label: 'HTTP Custom (.hc)', active: true }] : []),
                ...(cd.npvsContainer ? [{ id: 'npvs', label: 'NPV Tunnel (.npvs / .npvt)', active: true }] : []),
                ...(cd.haTunnelContainer ? [{ id: 'hatunnel', label: 'HA Tunnel (.hat)', active: true }] : []),
                ...(cd.v2boxContainer ? [{ id: 'v2box', label: 'V2Box (.v2box)', active: true }] : []),
                ...(cd.netmodContainer ? [{ id: 'netmod', label: 'NetMod (.nm)', active: true }] : []),
                ...(cd.sscContainer ? [{ id: 'ssc', label: 'SSH Custom (Ssc://)', active: true }] : []),
                ...(cd.httpWeakContainer ? [{ id: 'httpweak', label: 'HTTP Weak / Tweak (.ht)', active: true }] : []),
                ...(cd.darkTunnelContainer ? [{ id: 'darktunnel', label: 'Dark Tunnel (.dark)', active: true }] : []),
                ...(cd.creebContainer ? [{ id: 'creeb', label: 'Creeb Injector (CREEBINJ)', active: true }] : []),
                { id: 'v2ray', label: 'V2Ray / Xray Core', active: cd.v2ray.present },
                { id: 'dnstt', label: 'SlowDNS (DNSTT)', active: cd.slowDns.present },
                { id: 'ssh_proxy', label: 'SSH / Proxy / Payload / SSL', active: cd.ssh.present || cd.proxyAndPayload.present },
                { id: 'hysteria2', label: 'Hysteria2 (QUIC)', active: cd.hysteria2.present },
                { id: 'wireguard', label: 'WireGuard & Slipstream', active: cd.wireguard.present || cd.slipstream.present },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveProtocolTab(tab.id as any)}
                  className={`px-3 sm:px-3.5 py-1.5 sm:py-2 rounded-xl text-xs font-semibold transition flex items-center gap-2 cursor-pointer whitespace-nowrap shrink-0 sm:shrink ${activeProtocolTab === tab.id
                    ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                    : 'bg-slate-900/90 hover:bg-slate-800 text-slate-300 border border-slate-800'
                    }`}
                >
                  <span>{tab.label}</span>
                  {tab.active && (
                    <span
                      className={`w-2 h-2 rounded-full ${activeProtocolTab === tab.id ? 'bg-slate-950' : 'bg-emerald-400'
                        }`}
                    />
                  )}
                </button>
              ))}
            </div>
            <span className="text-[11px] sm:text-xs text-slate-500 shrink-0">
              Switch tabs to inspect any connection method block in detail
            </span>
          </div>

          {/* 5. Protocol Inspection Grid + Live Network Probes */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Left Column: Detailed Protocol Parameter Cards (7 cols) */}
            <div className="lg:col-span-7 space-y-6">
              {/* ==================== HTTP INJECTOR (.EHI) INSPECTOR CARD ==================== */}
              {showHttpInjectorCard && cd.httpInjectorContainer && (
                <div className="bg-slate-900/75 border border-sky-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-sky-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        HTTP Injector (<code className="text-sky-300 break-all">{cd.httpInjectorContainer.fileName || 'config.ehi'}</code>)
                      </h3>
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-sky-500/20 text-sky-300 border border-sky-500/30 whitespace-nowrap">
                        {cd.httpInjectorContainer.appName} ({cd.httpInjectorContainer.appVersion})
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                      {cd.httpInjectorContainer.payload && (
                        <button
                          type="button"
                          onClick={() => copyText('ehiPayload', cd.httpInjectorContainer!.payload)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-sky-500/20 hover:bg-sky-500/30 text-sky-300 border border-sky-500/30 cursor-pointer"
                        >
                          {copiedKey === 'ehiPayload' ? 'Copied Payload!' : 'Copy Payload'}
                        </button>
                      )}
                      {(cd.httpInjectorContainer.sshServer || cd.httpInjectorContainer.sshUser) && (
                        <button
                          type="button"
                          onClick={() => copyText('ehiSsh', `${cd.httpInjectorContainer!.sshServer}:${cd.httpInjectorContainer!.sshPort}@${cd.httpInjectorContainer!.sshUser}:${cd.httpInjectorContainer!.sshPass}`)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
                        >
                          {copiedKey === 'ehiSsh' ? 'Copied SSH!' : 'Copy SSH Config'}
                        </button>
                      )}
                      {cd.httpInjectorContainer.v2rayUuid && (
                        <button
                          type="button"
                          onClick={() => copyText('ehiV2ray', `vmess://${cd.httpInjectorContainer!.v2rayUuid}@${cd.httpInjectorContainer!.v2rayServer}:${cd.httpInjectorContainer!.v2rayPort}`)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/30 cursor-pointer"
                        >
                          {copiedKey === 'ehiV2ray' ? 'Copied VMess!' : 'Copy VMess'}
                        </button>
                      )}
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-sky-500/15 text-sky-300 border border-sky-500/30">
                        {cd.httpInjectorContainer.wireFormat}
                      </span>
                    </div>
                  </div>

                  {/* Profile Metadata Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Config Name</span>
                      <span className="text-xs font-bold text-sky-300 font-mono truncate block">{cd.httpInjectorContainer.configName}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Tunnel Type</span>
                      <span className="text-xs font-bold text-emerald-300">{cd.httpInjectorContainer.tunnelTypeName}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Security & Lock</span>
                      <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cd.httpInjectorContainer.isLocked ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-400'}`}>
                          {cd.httpInjectorContainer.isLocked ? (cd.httpInjectorContainer.lockToDevice ? 'HWID Locked' : 'Locked') : 'Unlocked'}
                        </span>
                        {cd.httpInjectorContainer.burnAfterImport && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/20 text-amber-300">
                            Burn After Import
                          </span>
                        )}
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-cyan-500/20 text-cyan-300">
                          {cd.httpInjectorContainer.expiryDate || 'No Expiry'}
                        </span>
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Container Size</span>
                      <span className="text-xs font-mono text-sky-300">{cd.httpInjectorContainer.fileSize.toLocaleString()} B • Evozi EHI</span>
                    </div>
                  </div>

                  {/* Notes / Banner Message if present */}
                  {cd.httpInjectorContainer.configMessage && (
                    <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 text-xs">
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block mb-1">Config Note / Broadcast</span>
                      <p className="text-slate-200 leading-relaxed font-sans">{cd.httpInjectorContainer.configMessage}</p>
                    </div>
                  )}

                  {/* HTTP Payload Injection preview if present */}
                  {cd.httpInjectorContainer.payload && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold uppercase tracking-wider text-sky-300">
                          Simulated Wire Payload / HTTP Injection
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          Tokens: [crlf], [host], [protocol], [split]
                        </span>
                      </div>
                      <pre className="text-xs font-mono bg-slate-950 p-3.5 rounded-xl border border-sky-500/30 text-sky-200 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                        {cd.httpInjectorContainer.payload}
                      </pre>
                    </div>
                  )}

                  {/* Endpoints & Credentials Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block font-sans">SSH Host & Port</span>
                      <span className="text-cyan-300 font-semibold">{cd.httpInjectorContainer.sshServer ? `${cd.httpInjectorContainer.sshServer}:${cd.httpInjectorContainer.sshPort || '443'}` : 'Direct / Non-SSH'}</span>
                      {cd.httpInjectorContainer.sshUser && (
                        <div className="text-[11px] text-slate-400 mt-1">User: <span className="text-white font-mono">{cd.httpInjectorContainer.sshUser}</span></div>
                      )}
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block font-sans">Remote Proxy (Bug Host)</span>
                      <span className="text-amber-300 font-semibold">{cd.httpInjectorContainer.remoteProxy || 'Direct TCP / SSL'}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block font-sans">SNI Bug Host</span>
                      <span className="text-emerald-300 font-semibold">{cd.httpInjectorContainer.sni || 'None / Plain TCP'}</span>
                    </div>
                  </div>

                  {/* V2Ray Details if present */}
                  {cd.httpInjectorContainer.v2rayUuid && (
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono bg-purple-950/20 p-3 rounded-xl border border-purple-500/30">
                      <div className="p-2 rounded-lg bg-slate-950/70 border border-purple-900/50">
                        <span className="text-[10px] text-purple-300 block font-sans">V2Ray Protocol / Core</span>
                        <span className="text-white font-semibold">{cd.httpInjectorContainer.v2rayProtocol?.toUpperCase() || 'VMESS'} / {cd.httpInjectorContainer.v2rayNetwork || 'ws'}</span>
                      </div>
                      <div className="p-2 rounded-lg bg-slate-950/70 border border-purple-900/50">
                        <span className="text-[10px] text-purple-300 block font-sans">V2Ray UUID</span>
                        <span className="text-purple-300 font-semibold truncate block">{cd.httpInjectorContainer.v2rayUuid}</span>
                      </div>
                      <div className="p-2 rounded-lg bg-slate-950/70 border border-purple-900/50">
                        <span className="text-[10px] text-purple-300 block font-sans">V2Ray Server:Port</span>
                        <span className="text-cyan-300 font-semibold truncate block">{cd.httpInjectorContainer.v2rayServer}:{cd.httpInjectorContainer.v2rayPort || '443'}</span>
                      </div>
                    </div>
                  )}

                  {/* SlowDNS Details if enabled */}
                  {cd.httpInjectorContainer.slowDnsEnabled && (
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono bg-cyan-950/20 p-3 rounded-xl border border-cyan-500/30">
                      <div className="p-2 rounded-lg bg-slate-950/70 border border-cyan-900/50">
                        <span className="text-[10px] text-cyan-300 block font-sans">SlowDNS Nameserver</span>
                        <span className="text-cyan-300 font-semibold truncate block">{cd.httpInjectorContainer.slowDnsNameserver || 'N/A'}</span>
                      </div>
                      <div className="p-2 rounded-lg bg-slate-950/70 border border-cyan-900/50">
                        <span className="text-[10px] text-cyan-300 block font-sans">SlowDNS Public Key</span>
                        <span className="text-purple-300 font-semibold truncate block">{cd.httpInjectorContainer.slowDnsPubkey || 'N/A'}</span>
                      </div>
                      <div className="p-2 rounded-lg bg-slate-950/70 border border-cyan-900/50">
                        <span className="text-[10px] text-cyan-300 block font-sans">DNS Resolver</span>
                        <span className="text-slate-300 font-semibold truncate block">{cd.httpInjectorContainer.slowDnsResolver || '1.1.1.1'}</span>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ==================== OPENTUNNEL (.TNL) INSPECTOR CARD ==================== */}
              {showOpenTunnelCard && cd.openTunnelContainer && (
                <div className="bg-slate-900/75 border border-indigo-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-indigo-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        OpenTunnel (<code className="text-indigo-300 break-all">{cd.openTunnelContainer.fileName || 'profile.tnl'}</code>)
                      </h3>
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 whitespace-nowrap">
                        {cd.openTunnelContainer.clientPackage} (v{cd.openTunnelContainer.appVersionCode})
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                      {cd.openTunnelContainer.v2rayConfig && (
                        <button
                          type="button"
                          onClick={() => copyText('tnlV2ray', cd.openTunnelContainer!.v2rayConfig)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 cursor-pointer"
                        >
                          {copiedKey === 'tnlV2ray' ? 'Copied V2Ray Link!' : 'Copy V2Ray Link'}
                        </button>
                      )}
                      {cd.openTunnelContainer.proxyPayload && (
                        <button
                          type="button"
                          onClick={() => copyText('tnlPayload', cd.openTunnelContainer!.proxyPayload)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 cursor-pointer"
                        >
                          {copiedKey === 'tnlPayload' ? 'Copied Payload!' : 'Copy Payload'}
                        </button>
                      )}
                      {(cd.openTunnelContainer.sshServer || cd.openTunnelContainer.sshUser) && (
                        <button
                          type="button"
                          onClick={() => copyText('tnlSsh', `${cd.openTunnelContainer!.sshServer}:${cd.openTunnelContainer!.sshPort}@${cd.openTunnelContainer!.sshUser}:${cd.openTunnelContainer!.sshPass}`)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
                        >
                          {copiedKey === 'tnlSsh' ? 'Copied SSH!' : 'Copy SSH Config'}
                        </button>
                      )}
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/15 text-indigo-300 border border-indigo-500/30">
                        OPL\x02 Wire Envelope
                      </span>
                    </div>
                  </div>

                  {/* Profile Metadata Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Profile Title</span>
                      <span className="text-xs font-bold text-cyan-300 font-mono truncate block">{cd.openTunnelContainer.configMessage}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Tunnel Mode</span>
                      <span className="text-xs font-bold text-emerald-300">{cd.openTunnelContainer.configModeName}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Security & Locks</span>
                      <div className="flex items-center gap-1.5 flex-wrap mt-0.5">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cd.openTunnelContainer.isProtected ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-400'}`}>
                          {cd.openTunnelContainer.isProtected ? 'Protected' : 'Unlocked'}
                        </span>
                        {cd.openTunnelContainer.lockHost && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-rose-500/20 text-rose-300">
                            Host Locked
                          </span>
                        )}
                        {cd.openTunnelContainer.hwidEnabled && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-purple-500/20 text-purple-300">
                            HWID
                          </span>
                        )}
                        {cd.openTunnelContainer.checkRoot && (
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-500/20 text-blue-300">
                            Root Block
                          </span>
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Container Metrics</span>
                      <span className="text-xs font-mono text-indigo-300">{cd.openTunnelContainer.fileSize.toLocaleString()} B • v{cd.openTunnelContainer.appVersionCode}</span>
                    </div>
                  </div>

                  {/* V2Ray Core Config if present */}
                  {cd.openTunnelContainer.v2rayConfig && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">
                          V2Ray / Xray Outbound Core Link
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          Native Core Integration
                        </span>
                      </div>
                      <pre className="text-xs font-mono bg-slate-950 p-3.5 rounded-xl border border-indigo-500/30 text-indigo-200 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                        {cd.openTunnelContainer.v2rayConfig}
                      </pre>
                    </div>
                  )}

                  {/* HTTP Payload if present */}
                  {cd.openTunnelContainer.proxyPayload && (
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-bold uppercase tracking-wider text-purple-300">
                          OpenTunnel Injected Header / Payload
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          Tokens: [crlf], [host_port], [protocol]
                        </span>
                      </div>
                      <pre className="text-xs font-mono bg-slate-950 p-3.5 rounded-xl border border-purple-500/30 text-purple-200 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                        {cd.openTunnelContainer.proxyPayload}
                      </pre>
                    </div>
                  )}

                  {/* Endpoints & Credentials Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block font-sans">SSH Host & Port</span>
                      <span className="text-cyan-300 font-semibold">{cd.openTunnelContainer.sshServer ? `${cd.openTunnelContainer.sshServer}:${cd.openTunnelContainer.sshPort || '22'}` : 'Not Configured (V2Ray / Proxy)'}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block font-sans">Remote Proxy (Bug Host)</span>
                      <span className="text-amber-300 font-semibold">{cd.openTunnelContainer.proxyRemote ? `${cd.openTunnelContainer.proxyRemote}:${cd.openTunnelContainer.proxyRemotePort || '8080'}` : (cd.openTunnelContainer.sslHost || 'Direct Connection')}</span>
                    </div>
                    <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                      <span className="text-[10px] text-slate-400 block font-sans">SNI / SSL Host</span>
                      <span className="text-emerald-300 font-semibold">{cd.openTunnelContainer.sslHost || 'None / Plain TCP'}</span>
                    </div>
                  </div>

                  {/* SlowDNS & Resolver Details */}
                  {(cd.openTunnelContainer.dnsnameserver || cd.openTunnelContainer.dnspu || cd.openTunnelContainer.dnsResolver) && (
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                      <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                        <span className="text-[10px] text-slate-400 block font-sans">DNSTT Nameserver</span>
                        <span className="text-cyan-300 font-semibold truncate block">{cd.openTunnelContainer.dnsnameserver || 'Default'}</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                        <span className="text-[10px] text-slate-400 block font-sans">DNSTT Public Key</span>
                        <span className="text-purple-300 font-semibold truncate block">{cd.openTunnelContainer.dnspu || 'None'}</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                        <span className="text-[10px] text-slate-400 block font-sans">DNS / UDP Resolver</span>
                        <span className="text-slate-300 font-semibold truncate block">{cd.openTunnelContainer.dnsResolver} (UDP: {cd.openTunnelContainer.udpResolver})</span>
                      </div>
                    </div>
                  )}

                  {/* Collapsible Decrypted XML Properties Viewer */}
                  {cd.openTunnelContainer.rawXml && (
                    <details className="group p-3 bg-slate-950/90 rounded-xl border border-slate-800 text-xs font-mono">
                      <summary className="flex items-center justify-between text-[11px] text-slate-400 cursor-pointer select-none">
                        <span className="font-semibold text-indigo-300">Decrypted XML Configuration Key-Values (Properties)</span>
                        <span className="text-[10px] text-slate-500 group-open:rotate-180 transition-transform">▼</span>
                      </summary>
                      <pre className="mt-2.5 p-3 rounded-lg bg-slate-900/90 text-slate-300 text-[11px] overflow-x-auto whitespace-pre-wrap leading-relaxed border border-slate-800">
                        {cd.openTunnelContainer.rawXml}
                      </pre>
                    </details>
                  )}

                  {/* Wire Verification Fingerprint */}
                  <div className="p-3 bg-slate-950/90 rounded-xl border border-slate-800 text-xs font-mono space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Header Fingerprint (Hex Preview)</span>
                      <span>PBKDF2-HMAC-SHA256 (100k) + AES-256-GCM</span>
                    </div>
                    <div className="text-[11px] text-slate-300 break-all bg-slate-900/80 p-2 rounded border border-slate-800">
                      {cd.openTunnelContainer.rawHexPreview || '4f504c02...'}
                    </div>
                  </div>
                </div>
              )}

              {/* ==================== HTTP CUSTOM (.HC) INSPECTOR CARD ==================== */}
              {showHcCard && cd.hcContainer && (
                <div className="bg-slate-900/75 border border-purple-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-purple-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        HTTP Custom (<code className="text-purple-300 break-all">{cd.hcContainer.profileName}</code>)
                      </h3>
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30 whitespace-nowrap">
                        xyz.easypro.httpcustom
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                      <button
                        type="button"
                        onClick={() => copyText('hcPayload', cd.hcContainer!.payload)}
                        className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-purple-500/20 hover:bg-purple-500/30 text-purple-300 border border-purple-500/30 cursor-pointer"
                      >
                        {copiedKey === 'hcPayload' ? 'Copied Payload!' : 'Copy Payload'}
                      </button>
                      <button
                        type="button"
                        onClick={() => copyText('hcSsh', `${cd.hcContainer!.sshServer}:${cd.hcContainer!.sshPort}@${cd.hcContainer!.sshUser}:${cd.hcContainer!.sshPass}`)}
                        className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
                      >
                        {copiedKey === 'hcSsh' ? 'Copied SSH!' : 'Copy SSH Config'}
                      </button>
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/15 text-purple-300 border border-purple-500/30">
                        {cd.hcContainer.containerStatus}
                      </span>
                    </div>
                  </div>

                  {/* Profile Metadata Grid */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3 bg-slate-950/60 p-3.5 rounded-xl border border-slate-800/80">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Profile Name</span>
                      <span className="text-xs font-bold text-cyan-300 font-mono truncate block">{cd.hcContainer.profileName}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Target Carrier / ISP</span>
                      <span className="text-xs font-bold text-emerald-300 truncate block">{cd.hcContainer.ispTarget}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Region & Core</span>
                      <span className="text-xs font-medium text-slate-300 truncate block">{cd.hcContainer.region}</span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Container Metrics</span>
                      <span className="text-xs font-mono text-purple-300 truncate block">{cd.hcContainer.aesBlocks} blocks ({cd.hcContainer.fileSize.toLocaleString()} B)</span>
                    </div>
                  </div>

                  {/* Engine Quick Switcher Banner */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-400">Tunnel Engine:</span>
                      {cd.hcContainer.isV2Ray ? (
                        <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                          ⚡ V2Ray (Xray-Core • libaio.so)
                        </span>
                      ) : (
                        <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                          🔐 SSH Tunnel Mode
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-[11px] text-slate-400">Re-inspect Engine:</span>
                      <button
                        type="button"
                        onClick={() => {
                          setProtocolMode('v2ray');
                          handleInspect(input, importedFileInfo?.name, 'v2ray');
                        }}
                        className={`px-2.5 py-1 rounded-lg text-xs font-bold transition cursor-pointer ${
                          cd.hcContainer.isV2Ray
                            ? 'bg-cyan-500 text-slate-950 shadow-sm'
                            : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
                        }`}
                      >
                        ⚡ Xray-Core
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setProtocolMode('ssh');
                          handleInspect(input, importedFileInfo?.name, 'ssh');
                        }}
                        className={`px-2.5 py-1 rounded-lg text-xs font-bold transition cursor-pointer ${
                          !cd.hcContainer.isV2Ray
                            ? 'bg-purple-500 text-slate-950 shadow-sm'
                            : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
                        }`}
                      >
                        🔐 SSH Mode
                      </button>
                    </div>
                  </div>

                  {/* Target Connection Endpoints */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-400">
                        {cd.hcContainer.isV2Ray ? 'V2Ray Outbound & Server Endpoint' : 'SSH Tunnel Outbound & Bug Host Configuration'}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        {cd.hcContainer.isV2Ray ? 'Port 443 / 80 • Xray Outbound Core' : 'Port 443 / 22 • TLS Handshake + WebSocket'}
                      </span>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
                      {cd.hcContainer.isV2Ray ? (
                        <>
                          <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block font-sans">Core Dispatcher</span>
                            <span className="text-cyan-300 font-semibold truncate block">libaio.so (dev/epro/xray)</span>
                          </div>
                          <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block font-sans">Protocol & Transport</span>
                            <span className="text-emerald-300 font-semibold truncate block">
                              {(cd.hcContainer.v2rayProtocol || cd.v2ray.protocol || 'VLESS').toUpperCase()} via {cd.v2ray.network?.toUpperCase() || 'WS'}
                            </span>
                          </div>
                          <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block font-sans">Target SNI / Bug Host</span>
                            <span className="text-amber-300 font-semibold truncate block">{cd.hcContainer.sni || cd.v2ray.sni || cd.hcContainer.remoteProxy || 'Cloud Endpoint'}</span>
                          </div>
                        </>
                      ) : (
                        <>
                          <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block font-sans">SSH Host & Port</span>
                            <span className="text-cyan-300 font-semibold">{cd.hcContainer.sshServer}:{cd.hcContainer.sshPort}</span>
                          </div>
                          <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block font-sans">Remote Proxy (Bug Host)</span>
                            <span className="text-amber-300 font-semibold">{cd.hcContainer.remoteProxy}</span>
                          </div>
                          <div className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block font-sans">SNI (Server Name)</span>
                            <span className="text-emerald-300 font-semibold">{cd.hcContainer.sni}</span>
                          </div>
                        </>
                      )}
                    </div>
                  </div>

                  {/* HTTP Custom Payload Inspector */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold uppercase tracking-wider text-purple-300">
                        HTTP Custom Injected Header / Payload
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        Tokens: [host], [crlf], [protocol], Upgrade: websocket
                      </span>
                    </div>
                    <pre className="text-xs font-mono bg-slate-950 p-3.5 rounded-xl border border-purple-500/30 text-purple-200 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                      {cd.hcContainer.payload}
                    </pre>
                  </div>

                  {/* Credentials / Core Engine Session */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    {cd.hcContainer.isV2Ray ? (
                      <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-300">V2Ray Dispatch Architecture</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 font-semibold">Active Engine</span>
                        </div>
                        <div className="font-mono text-slate-300 text-[11px] space-y-0.5">
                          <div>Runtime: <span className="text-cyan-300">Xray-Core (libaio.so)</span></div>
                          <div className="truncate">Outbound: <span className="text-amber-300">🔒 Controller Injected (App Sealed)</span></div>
                        </div>
                      </div>
                    ) : (
                      <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-300">SSH Authentication Credentials</span>
                          <span className="text-[10px] text-slate-400">Pre-configured</span>
                        </div>
                        <div className="font-mono text-slate-300 text-[11px] space-y-0.5">
                          <div>User: <span className="text-cyan-300">{cd.hcContainer.sshUser || 'none'}</span></div>
                          <div>Pass: <span className="text-amber-300">{cd.hcContainer.sshPass ? '••••••••' : 'none'}</span></div>
                        </div>
                      </div>
                    )}

                    <div className="p-3 bg-slate-950/70 rounded-xl border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-300">SlowDNS (DNSTT) Fallback</span>
                        <span className={`text-[10px] px-1.5 py-0.5 rounded font-semibold ${cd.hcContainer.slowDnsEnabled ? 'bg-emerald-500/15 text-emerald-300' : 'bg-slate-800 text-slate-500'}`}>
                          {cd.hcContainer.slowDnsEnabled ? 'Active' : 'Disabled'}
                        </span>
                      </div>
                      <div className="font-mono text-slate-300 text-[11px] truncate space-y-0.5">
                        <div className="truncate">NS: <span className="text-cyan-300">{cd.hcContainer.slowDnsNameserver || 'none'}</span></div>
                        <div>DNS: <span className="text-slate-400">{cd.hcContainer.slowDnsResolver || 'none'}</span></div>
                      </div>
                    </div>
                  </div>

                  {/* Wire Verification Fingerprint */}
                  <div className="p-3 bg-slate-950/90 rounded-xl border border-slate-800 text-xs font-mono space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>Header Fingerprint (Hex Preview)</span>
                      <span>{cd.hcContainer.cipherMethod}</span>
                    </div>
                    <div className="text-[11px] text-slate-300 break-all bg-slate-900/80 p-2 rounded border border-slate-800">
                      {cd.hcContainer.rawHexPreview || 'd7e4808c9ef5e2c3aca4f1d3e0dcdc94f7e593fda1ab80b7d4d99bf0e5c6fca2'}
                    </div>
                  </div>
                </div>
              )}

              {/* ==================== NPV TUNNEL (.NPVS) SEALED ENVELOPE INSPECTOR CARD ==================== */}
              {showNpvsCard && cd.npvsContainer && (
                <div className="bg-slate-900/75 border border-emerald-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        NPV Tunnel Sealed Config (<code className="text-emerald-300 break-all">{cd.npvsContainer.profileName}</code>)
                      </h3>
                    </div>
                    <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                      {cd.npvsContainer.generatedVlessUri && (
                        <button
                          type="button"
                          onClick={() => copyText('npvsVlessUri', cd.npvsContainer!.generatedVlessUri!)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 cursor-pointer"
                        >
                          {copiedKey === 'npvsVlessUri' ? 'Copied VLESS Link!' : 'Copy VLESS Share Link'}
                        </button>
                      )}
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/15 text-cyan-300 border border-cyan-500/30 whitespace-nowrap">
                        NPVS-v{cd.npvsContainer.version} SEALED ENVELOPE
                      </span>
                    </div>
                  </div>

                  {/* Envelope Metadata Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {[
                      { label: 'Profile Name', value: cd.npvsContainer.profileName },
                      { label: 'Client Application', value: cd.npvsContainer.clientPackage },
                      { label: 'Wire Specification', value: `NPVS-v${cd.npvsContainer.version}` },
                      { label: 'Cipher Suite', value: cd.npvsContainer.cipherSuite },
                      { label: 'Target Outbound Host', value: cd.npvsContainer.targetServer },
                      { label: 'Target Port', value: String(cd.npvsContainer.targetPort) },
                      { label: 'SNI (Server Name)', value: cd.npvsContainer.sni },
                      { label: 'Protocol Mode', value: cd.npvsContainer.protocol },
                      { label: 'Payload Envelope', value: `${cd.npvsContainer.payloadLength.toLocaleString()} bytes (${cd.npvsContainer.payloadFormat})` },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-emerald-300/90">
                            {item.label}
                          </div>
                          <div className="text-sm font-mono text-slate-100 truncate mt-0.5" title={item.value}>
                            {item.value}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyText(item.label, item.value)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                        >
                          {copiedKey === item.label ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    ))}
                  </div>

                  {/* Ephemeral ECDH Public Key */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Ephemeral Recipient Public Key (P-256 ECDH • 33 Bytes Compressed)
                      </span>
                      <button
                        type="button"
                        onClick={() => copyText('ecdhPub', cd.npvsContainer!.ephemeralPublicKey)}
                        className="text-xs text-cyan-400 hover:underline cursor-pointer"
                      >
                        {copiedKey === 'ecdhPub' ? 'Copied Key!' : 'Copy Hex'}
                      </button>
                    </div>
                    <div className="font-mono text-xs text-emerald-300 break-all bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                      {cd.npvsContainer.ephemeralPublicKey}
                    </div>
                  </div>

                  {/* Verified VLESS Outbound Share Link */}
                  {cd.npvsContainer.generatedVlessUri && (
                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-emerald-500/30 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                          Verified V2Ray (VLESS-WebSocket-TLS) Direct Link
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText('vlessUri', cd.npvsContainer!.generatedVlessUri!)}
                          className="text-xs text-cyan-400 hover:underline cursor-pointer"
                        >
                          {copiedKey === 'vlessUri' ? 'Copied Link!' : 'Copy Link'}
                        </button>
                      </div>
                      <div className="font-mono text-xs text-slate-200 break-all bg-slate-900 p-2.5 rounded-lg border border-slate-800 select-all">
                        {cd.npvsContainer.generatedVlessUri}
                      </div>
                    </div>
                  )}

                  {/* IEEE P1363 Signature */}
                  {cd.npvsContainer.signatureR && (
                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                      <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        IEEE P1363 ECDSA Cryptographic Envelope Signature (64 Bytes)
                      </div>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">SIGNATURE (r):</span>
                          <span className="text-slate-300 break-all">{cd.npvsContainer.signatureR}</span>
                        </div>
                        <div className="p-2 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-500 block text-[10px]">SIGNATURE (s):</span>
                          <span className="text-slate-300 break-all">{cd.npvsContainer.signatureS}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ==================== CREEB INJECTOR (.CREEB / CREEBINJ-<ID>) INSPECTOR CARD ==================== */}
              {showCreebCard && cd.creebContainer && (
                <div className="bg-slate-900/75 border border-emerald-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  {/* Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shrink-0" />
                      <div>
                        <h3 className="text-base font-bold text-white truncate max-w-full">
                          Creeb Injector{' '}
                          <span className="text-emerald-300">
                            ({cd.creebContainer.profileName || cd.creebContainer.fullToken})
                          </span>
                        </h3>
                        <div className="text-[11px] font-mono text-slate-400">
                          {cd.creebContainer.appName} • <code className="text-emerald-300/80">{cd.creebContainer.fullToken}</code>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 whitespace-nowrap">
                        {cd.creebContainer.tunnelTypeName || `Type ${cd.creebContainer.tunnelType}`}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${cd.creebContainer.isLocked
                          ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                          : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                          }`}
                      >
                        {cd.creebContainer.isLocked ? 'Locked Profile' : 'Unlocked'}
                      </span>
                      {cd.creebContainer.security?.validadeFormatted && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-cyan-300 border border-slate-700">
                          Expires: {cd.creebContainer.security.validadeFormatted}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Primary Configuration Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-[11px] font-semibold uppercase tracking-wider text-emerald-300/90">
                          Target Server Host:Port
                        </div>
                        <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                          {cd.creebContainer.serverHost
                            ? `${cd.creebContainer.serverHost}:${cd.creebContainer.serverPort || '443'}`
                            : cd.creebContainer.hostPort || 'Not specified'}
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() =>
                          copyText(
                            'Creeb Server',
                            cd.creebContainer?.serverHost
                              ? `${cd.creebContainer.serverHost}:${cd.creebContainer.serverPort || '443'}`
                              : cd.creebContainer?.hostPort || ''
                          )
                        }
                        className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                      >
                        {copiedKey === 'Creeb Server' ? 'Copied!' : 'Copy'}
                      </button>
                    </div>

                    <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-[11px] font-semibold uppercase tracking-wider text-emerald-300/90">
                          SSH Credentials
                        </div>
                        <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                          {cd.creebContainer.sshUser ? (
                            <>
                              <span className="text-slate-300">{cd.creebContainer.sshUser}</span>
                              <span className="text-slate-500"> : </span>
                              <span className="text-cyan-300">{cd.creebContainer.sshPass || '••••'}</span>
                            </>
                          ) : (
                            <span className="text-slate-500">No SSH Credentials</span>
                          )}
                        </div>
                      </div>
                      {cd.creebContainer.sshUser && (
                        <button
                          type="button"
                          onClick={() =>
                            copyText(
                              'Creeb SSH',
                              `${cd.creebContainer?.sshUser}:${cd.creebContainer?.sshPass}`
                            )
                          }
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                        >
                          {copiedKey === 'Creeb SSH' ? 'Copied!' : 'Copy'}
                        </button>
                      )}
                    </div>

                    <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-[11px] font-semibold uppercase tracking-wider text-emerald-300/90">
                          Tunnel Mode
                        </div>
                        <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                          {cd.creebContainer.tunnelTypeName || `Tunnel Type ${cd.creebContainer.tunnelType}`}
                        </div>
                      </div>
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                        ID: {cd.creebContainer.tunnelType ?? 8}
                      </span>
                    </div>

                    {cd.creebContainer.slowDnsPubkey && (
                      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2 sm:col-span-2 lg:col-span-3">
                        <div className="min-w-0 flex-1">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-emerald-300/90">
                            SlowDNS (DNSTT) Public Key (chaveKey)
                          </div>
                          <div className="text-xs font-mono text-cyan-300 truncate mt-0.5">
                            {cd.creebContainer.slowDnsPubkey}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyText('SlowDNS Pubkey', cd.creebContainer?.slowDnsPubkey || '')}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                        >
                          {copiedKey === 'SlowDNS Pubkey' ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Injected HTTP Request Payload */}
                  {cd.creebContainer.proxyPayload && (
                    <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="text-xs font-semibold uppercase tracking-wider text-emerald-300">
                          Injected HTTP Payload (proxyPayload)
                        </div>
                        <button
                          type="button"
                          onClick={() => copyText('Creeb Payload', cd.creebContainer?.proxyPayload || '')}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 cursor-pointer"
                        >
                          {copiedKey === 'Creeb Payload' ? 'Copied!' : 'Copy Payload'}
                        </button>
                      </div>
                      <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800/80 text-xs font-mono text-emerald-300/95 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                        {cd.creebContainer.proxyPayload}
                      </pre>
                    </div>
                  )}

                  {/* V2Ray VMess Outbound Card */}
                  {(cd.creebContainer.v2rayJsonRaw || cd.creebContainer.v2rayParsed) && (
                    <div className="p-4 rounded-xl bg-slate-950/90 border border-purple-500/30 space-y-3">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-purple-900/40 pb-2">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-purple-400"></span>
                          <h4 className="text-xs font-bold uppercase tracking-wider text-purple-300">
                            V2Ray VMess Outbound Configuration
                          </h4>
                          {cd.creebContainer.v2rayParsed?.ps && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                              {cd.creebContainer.v2rayParsed.ps}
                            </span>
                          )}
                        </div>
                        {cd.creebContainer.v2rayJsonRaw && (
                          <button
                            type="button"
                            onClick={() => copyText('VMess Link', cd.creebContainer?.v2rayJsonRaw || '')}
                            className="px-2.5 py-1 rounded bg-purple-900/50 hover:bg-purple-800/60 text-purple-200 text-xs font-mono font-medium border border-purple-700/50 cursor-pointer"
                          >
                            {copiedKey === 'VMess Link' ? 'Copied VMess Link!' : 'Copy vmess:// Link'}
                          </button>
                        )}
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-xs font-mono">
                        <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
                          <span className="text-[10px] uppercase font-semibold text-slate-500 block">Server Address</span>
                          <span className="text-slate-100 font-bold truncate block">
                            {cd.creebContainer.v2rayParsed?.add || cd.creebContainer.serverHost || 'umc-cdn.secb2b.com'}:
                            {cd.creebContainer.v2rayParsed?.port || cd.creebContainer.serverPort || '443'}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
                          <span className="text-[10px] uppercase font-semibold text-slate-500 block">Transport Network</span>
                          <span className="text-cyan-300 font-bold truncate block">
                            {cd.creebContainer.v2rayParsed?.net?.toUpperCase() || 'WS'} ({cd.creebContainer.v2rayParsed?.path || '/vmess'})
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800">
                          <span className="text-[10px] uppercase font-semibold text-slate-500 block">TLS & SNI Bug Host</span>
                          <span className="text-emerald-300 font-bold truncate block">
                            {cd.creebContainer.v2rayParsed?.sni || cd.creebContainer.v2rayParsed?.host || 'None'}
                          </span>
                        </div>

                        <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 sm:col-span-2 lg:col-span-3 flex items-center justify-between gap-2">
                          <div className="min-w-0">
                            <span className="text-[10px] uppercase font-semibold text-slate-500 block">VMess User UUID</span>
                            <span className="text-purple-300 font-bold truncate block">
                              {cd.creebContainer.v2rayParsed?.id || 'd437a329-a85c-4752-92e3-816389dc6a44'}
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => copyText('VMess UUID', cd.creebContainer?.v2rayParsed?.id || '')}
                            className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                          >
                            {copiedKey === 'VMess UUID' ? 'Copied!' : 'Copy'}
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Security, Expiry & Anti-Tamper Details */}
                  {cd.creebContainer.security && (
                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                      <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Security & Export Restrictions
                      </div>
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                          <span className="text-slate-500 text-[10px] block">ROOT PROTECTION</span>
                          <span className={cd.creebContainer.security.bloquearRoot ? 'text-amber-300' : 'text-slate-300'}>
                            {cd.creebContainer.security.bloquearRoot ? 'Root Blocked' : 'Disabled'}
                          </span>
                        </div>
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                          <span className="text-slate-500 text-[10px] block">HWID LOCK</span>
                          <span className={cd.creebContainer.security.blockHwid ? 'text-purple-300' : 'text-slate-300'}>
                            {cd.creebContainer.security.blockHwid ? 'Device Locked' : 'None'}
                          </span>
                        </div>
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                          <span className="text-slate-500 text-[10px] block">PLAY STORE ONLY</span>
                          <span className={cd.creebContainer.security.onlyPlayStore ? 'text-cyan-300' : 'text-slate-300'}>
                            {cd.creebContainer.security.onlyPlayStore ? 'PlayStore Only' : 'Disabled'}
                          </span>
                        </div>
                        <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
                          <span className="text-slate-500 text-[10px] block">PASSWORD LOCK</span>
                          <span className={cd.creebContainer.security.requiresPassword ? 'text-amber-300' : 'text-slate-300'}>
                            {cd.creebContainer.security.requiresPassword ? 'Password Guard' : 'None'}
                          </span>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Message / Notice */}
                  {cd.creebContainer.message && (
                    <div className="p-3 rounded-xl bg-emerald-950/30 border border-emerald-500/30 flex items-center gap-2.5">
                      <span className="text-lg">📢</span>
                      <div>
                        <div className="text-[10px] font-bold uppercase tracking-wider text-emerald-400">
                          Profile Author Note
                        </div>
                        <div className="text-xs font-medium text-emerald-200">
                          {cd.creebContainer.message}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Raw Profile Bundle JSON Viewer */}
                  {cd.creebContainer.rawBundleJson && (
                    <details className="group rounded-xl bg-slate-950/70 border border-slate-800 overflow-hidden text-xs">
                      <summary className="px-3.5 py-2.5 cursor-pointer font-semibold text-slate-400 hover:text-slate-200 flex items-center justify-between">
                        <span>View Raw Decoded Creeb Bundle JSON</span>
                        <span className="text-slate-500 group-open:rotate-180 transition">▼</span>
                      </summary>
                      <div className="p-3 border-t border-slate-800 bg-slate-950">
                        <div className="flex justify-end mb-2">
                          <button
                            type="button"
                            onClick={() => copyText('Creeb JSON', cd.creebContainer?.rawBundleJson || '')}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 cursor-pointer"
                          >
                            {copiedKey === 'Creeb JSON' ? 'Copied!' : 'Copy JSON'}
                          </button>
                        </div>
                        <pre className="text-[11px] font-mono text-slate-300 max-h-64 overflow-y-auto whitespace-pre leading-relaxed">
                          {cd.creebContainer.rawBundleJson}
                        </pre>
                      </div>
                    </details>
                  )}

                  {/* Interactive Cloud API URL & Live Server Endpoint Verifier */}
                  <div className="p-4 rounded-xl bg-cyan-950/20 border border-cyan-500/30 space-y-3">
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                        Verify Cloud Endpoint or Target Server / SNI / SlowDNS for {cd.creebContainer.fullToken}
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Enter your custom Cloud API URL (if self-hosted) or enter the target Server IP/Domain, Port, SNI, or SlowDNS Nameserver backing <code className="text-emerald-300">{cd.creebContainer.fullToken}</code> to run live TCP, TLS/SNI, and UDP/53 DNSTT probes:
                      </p>
                    </div>

                    <div>
                      <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                        Custom Cloud API URL (Optional — e.g. https://your-api.com/cloud/{cd.creebContainer.fullToken})
                      </label>
                      <input
                        type="text"
                        value={customCloudUrl}
                        onChange={(e) => setCustomCloudUrl(e.target.value)}
                        placeholder={`https://your-cloud-server.com/api/config/${cd.creebContainer.fullToken}`}
                        className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-100"
                      />
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                          Server IP / Domain
                        </label>
                        <input
                          type="text"
                          value={manualServerHost}
                          onChange={(e) => setManualServerHost(e.target.value)}
                          placeholder="e.g. 169.255.187.58 or ssh.myserver.com"
                          className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-100"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                          Server Port (SSH / SSL / V2Ray)
                        </label>
                        <input
                          type="text"
                          value={manualServerPort}
                          onChange={(e) => setManualServerPort(e.target.value)}
                          placeholder="443 or 22"
                          className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-100"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                          SSL / TLS SNI (Bug Host)
                        </label>
                        <input
                          type="text"
                          value={manualSni}
                          onChange={(e) => setManualSni(e.target.value)}
                          placeholder="e.g. cloudflare.com"
                          className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-100"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] font-semibold uppercase text-slate-400 mb-1">
                          SlowDNS (DNSTT) Nameserver
                        </label>
                        <input
                          type="text"
                          value={manualNameserver}
                          onChange={(e) => setManualNameserver(e.target.value)}
                          placeholder="e.g. nexus.amokhan.xyz"
                          className="w-full rounded-lg bg-slate-950 border border-slate-700 px-3 py-1.5 text-xs font-mono text-slate-100"
                        />
                      </div>
                    </div>

                    <div className="flex justify-end">
                      <button
                        type="button"
                        disabled={loading}
                        onClick={() => handleInspect()}
                        className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-400 to-teal-500 text-slate-950 font-bold text-xs cursor-pointer"
                      >
                        Run Live Verification Probe for {cd.creebContainer.fullToken}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* ==================== HTTP WEAK / HTTP TWEAK MULTI-PROTOCOL INSPECTOR CARD ==================== */}
              {showHttpWeakCard && cd.httpWeakContainer && (
                <div className="bg-slate-900/75 border border-violet-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  {/* Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-violet-400 shrink-0" />
                      <div>
                        <h3 className="text-base font-bold text-white truncate max-w-full flex items-center gap-2">
                          <span>HTTP Weak / HTTP Tweak Multi-Protocol Inspector</span>
                          <span className="text-xs font-normal text-violet-300 font-mono">
                            ({cd.httpWeakContainer.profileName})
                          </span>
                        </h3>
                        <div className="text-[11px] font-mono text-slate-400">
                          {cd.httpWeakContainer.appName} • v{cd.httpWeakContainer.versionName} • <code className="text-violet-300/80">{cd.httpWeakContainer.tokenOrFile}</code>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-violet-500/15 text-violet-300 border border-violet-500/30 whitespace-nowrap uppercase">
                        Primary: {cd.httpWeakContainer.tunnelType}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${cd.httpWeakContainer.restrictions.cloudProtected
                            ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                          }`}
                      >
                        {cd.httpWeakContainer.restrictions.cloudProtected ? 'Cloud Protected' : 'Unlocked'}
                      </span>
                      {cd.httpWeakContainer.restrictions.allowedCarrierCodes.length > 0 && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-sky-500/15 text-sky-300 border border-sky-500/30">
                          {cd.httpWeakContainer.restrictions.allowedCarrierCodes.length} Carriers Locked
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Summary Metric Pills */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-2 text-xs">
                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Primary Mode</div>
                      <div className="text-slate-100 font-mono font-bold mt-0.5 truncate uppercase text-violet-300">
                        {cd.httpWeakContainer.tunnelType}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Play Store Lock</div>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.httpWeakContainer.restrictions.requireStoreInstall ? 'text-amber-400' : 'text-slate-400'}`}>
                        {cd.httpWeakContainer.restrictions.requireStoreInstall ? 'Enforced' : 'Unlocked'}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Root Guard</div>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.httpWeakContainer.restrictions.blockRoot ? 'text-rose-400' : 'text-slate-400'}`}>
                        {cd.httpWeakContainer.restrictions.blockRoot ? 'Block Root' : 'Allowed'}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Network Lock</div>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.httpWeakContainer.restrictions.mobileOnly ? 'text-amber-400' : 'text-slate-400'}`}>
                        {cd.httpWeakContainer.restrictions.mobileOnly ? 'Mobile Only' : 'All Networks'}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Hotspot Reshare</div>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.httpWeakContainer.restrictions.allowReshare ? 'text-emerald-400' : 'text-rose-400'}`}>
                        {cd.httpWeakContainer.restrictions.allowReshare ? 'Permitted' : 'Prohibited'}
                      </div>
                    </div>
                    <div className="p-2.5 rounded-xl bg-slate-950/70 border border-slate-800">
                      <div className="text-[10px] uppercase font-bold text-slate-400">Profile Expiry</div>
                      <div className="text-slate-200 font-mono text-[11px] mt-0.5 truncate">
                        {cd.httpWeakContainer.restrictions.expireDateFormatted}
                      </div>
                    </div>
                  </div>

                  {/* Multi-Protocol Protocol Switcher Tabs */}
                  <div className="space-y-3">
                    <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                      <div className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-violet-400" />
                        Multi-Protocol Configuration Data Extractor
                      </div>
                      <span className="text-[10px] font-mono text-slate-400">
                        Select protocol to view actual extracted parameters
                      </span>
                    </div>

                    <div className="flex items-center gap-1.5 overflow-x-auto pb-1 max-w-full">
                      {[
                        { id: 'openvpn', label: 'OpenVPN (TCP/UDP)' },
                        { id: 'ssh', label: 'SSH & Custom Payload' },
                        { id: 'v2ray', label: 'V2Ray / Xray Core' },
                        { id: 'hysteria', label: 'Hysteria 2 / UDP' },
                        { id: 'slowdns', label: 'SlowDNS (MasterDNS)' },
                        { id: 'wireguard', label: 'WireGuard' },
                      ].map((subTab) => (
                        <button
                          key={subTab.id}
                          type="button"
                          onClick={() => setHttpWeakProtocolTab(subTab.id as any)}
                          className={`px-3 py-1.5 rounded-lg text-xs font-semibold cursor-pointer whitespace-nowrap transition ${httpWeakProtocolTab === subTab.id
                              ? 'bg-violet-600 text-white font-bold shadow-sm shadow-violet-600/30'
                              : 'bg-slate-950/80 hover:bg-slate-800 text-slate-400 border border-slate-800'
                            }`}
                        >
                          {subTab.label}
                        </button>
                      ))}
                    </div>

                    {/* Sub-Panel: OpenVPN */}
                    {httpWeakProtocolTab === 'openvpn' && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">OpenVPN Endpoint</span>
                            <span className="text-violet-300 font-mono font-bold break-all">
                              {cd.httpWeakContainer.protocols.openvpn.endpoint}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Protocol</span>
                            <span className="text-slate-200 font-mono uppercase">
                              {cd.httpWeakContainer.protocols.openvpn.protocol}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Preserved Ports</span>
                            <span className="text-slate-200 font-mono">
                              {cd.httpWeakContainer.protocols.openvpn.preservedPorts.join(', ') || '1194, 443'}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Private Key Passphrase</span>
                            <span className="text-slate-300 font-mono">
                              {cd.httpWeakContainer.protocols.openvpn.hasPrivateKeyPassword ? 'Password Set' : 'None / Embedded'}
                            </span>
                          </div>
                        </div>

                        {cd.httpWeakContainer.protocols.openvpn.ovpnConfig && (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-bold uppercase text-slate-400">OpenVPN Profile Directives (.ovpn)</span>
                              <button
                                type="button"
                                onClick={() => copyText('OVPN Config', cd.httpWeakContainer?.protocols.openvpn.ovpnConfig || '')}
                                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-slate-300 cursor-pointer"
                              >
                                {copiedKey === 'OVPN Config' ? 'Copied!' : 'Copy OVPN'}
                              </button>
                            </div>
                            <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-36 leading-relaxed">
                              {cd.httpWeakContainer.protocols.openvpn.ovpnConfig}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Sub-Panel: SSH & Payload */}
                    {httpWeakProtocolTab === 'ssh' && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">SSH Server Endpoint</span>
                            <span className="text-cyan-300 font-mono font-bold break-all">
                              {cd.httpWeakContainer.protocols.ssh.hosts[0]}:{cd.httpWeakContainer.protocols.ssh.ports[0]}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Credentials</span>
                            <span className="text-slate-200 font-mono">
                              {cd.httpWeakContainer.protocols.ssh.username} : {cd.httpWeakContainer.protocols.ssh.password || '••••••'}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Remote HTTP Proxy</span>
                            <span className="text-slate-300 font-mono">
                              {cd.httpWeakContainer.protocols.ssh.proxy.hosts[0]}:{cd.httpWeakContainer.protocols.ssh.proxy.ports[0]}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">SNI & Cipher</span>
                            <span className="text-indigo-300 font-mono text-[11px] truncate block">
                              {cd.httpWeakContainer.protocols.ssh.proxy.sni} ({cd.httpWeakContainer.protocols.ssh.cipherAlias})
                            </span>
                          </div>
                        </div>

                        {cd.httpWeakContainer.protocols.ssh.proxy.payload && (
                          <div className="space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-bold uppercase text-slate-400">Injected HTTP Request Payload</span>
                              <button
                                type="button"
                                onClick={() => copyText('HTTP Payload', cd.httpWeakContainer?.protocols.ssh.proxy.payload || '')}
                                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-[10px] text-slate-300 cursor-pointer"
                              >
                                {copiedKey === 'HTTP Payload' ? 'Copied!' : 'Copy Payload'}
                              </button>
                            </div>
                            <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-300 overflow-x-auto leading-relaxed">
                              {cd.httpWeakContainer.protocols.ssh.proxy.payload}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Sub-Panel: V2Ray / Xray Core */}
                    {httpWeakProtocolTab === 'v2ray' && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Outbound Server</span>
                            <span className="text-cyan-300 font-mono font-bold break-all">
                              {cd.httpWeakContainer.protocols.v2ray.serverHost}:{cd.httpWeakContainer.protocols.v2ray.serverPort}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">UUID / User ID</span>
                            <span className="text-slate-300 font-mono text-[11px] break-all">
                              {cd.httpWeakContainer.protocols.v2ray.uuid}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Transport Network & Security</span>
                            <span className="text-purple-300 font-mono uppercase">
                              {cd.httpWeakContainer.protocols.v2ray.network} + {cd.httpWeakContainer.protocols.v2ray.security}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">WS Path & SNI</span>
                            <span className="text-indigo-300 font-mono text-[11px] break-all">
                              {cd.httpWeakContainer.protocols.v2ray.wsPath} ({cd.httpWeakContainer.protocols.v2ray.sni})
                            </span>
                          </div>
                        </div>

                        <div className="text-[11px] font-mono text-slate-400">
                          Supported Core Protocols: <span className="text-slate-300">{cd.httpWeakContainer.protocols.v2ray.transports.join(', ')}</span>
                        </div>
                      </div>
                    )}

                    {/* Sub-Panel: Hysteria 2 / UDP */}
                    {httpWeakProtocolTab === 'hysteria' && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Hysteria Endpoint</span>
                            <span className="text-pink-300 font-mono font-bold break-all">
                              {cd.httpWeakContainer.protocols.hysteria.endpoint}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Port Sets / Hopping</span>
                            <span className="text-slate-200 font-mono">
                              {cd.httpWeakContainer.protocols.hysteria.portSets}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Bandwidth Limits</span>
                            <span className="text-emerald-300 font-mono">
                              ↑ {cd.httpWeakContainer.protocols.hysteria.uploadMbps} Mbps / ↓ {cd.httpWeakContainer.protocols.hysteria.downloadMbps} Mbps
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Authentication & Obfs</span>
                            <span className="text-amber-300 font-mono text-[11px] truncate block">
                              Auth: {cd.httpWeakContainer.protocols.hysteria.authentication} | Obfs: {cd.httpWeakContainer.protocols.hysteria.obfuscationPassword || 'None'}
                            </span>
                          </div>
                        </div>

                        <div className="text-[11px] font-mono text-slate-400">
                          QUIC ALPN: <span className="text-slate-300">{cd.httpWeakContainer.protocols.hysteria.alpn.join(', ')}</span> • Receive Window: <span className="text-slate-300">{cd.httpWeakContainer.protocols.hysteria.receiveWindow}</span> • Hop Interval: <span className="text-slate-300">{cd.httpWeakContainer.protocols.hysteria.hopIntervalSeconds}s</span>
                        </div>
                      </div>
                    )}

                    {/* Sub-Panel: SlowDNS / MasterDNS */}
                    {httpWeakProtocolTab === 'slowdns' && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Query Domain</span>
                            <span className="text-purple-300 font-mono font-bold break-all">
                              {cd.httpWeakContainer.protocols.slowdns.domain}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">DNS Family & Variant</span>
                            <span className="text-slate-200 font-mono uppercase">
                              {cd.httpWeakContainer.protocols.slowdns.family} ({cd.httpWeakContainer.protocols.slowdns.variant})
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Nameservers</span>
                            <span className="text-slate-300 font-mono">
                              {cd.httpWeakContainer.protocols.slowdns.nameservers.join(', ')}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Encryption PubKey</span>
                            <span className="text-emerald-300 font-mono text-[11px] truncate block">
                              {cd.httpWeakContainer.protocols.slowdns.encryptionKey}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Sub-Panel: WireGuard */}
                    {httpWeakProtocolTab === 'wireguard' && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3">
                        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-2.5 text-xs">
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">WireGuard Peer Endpoint</span>
                            <span className="text-orange-300 font-mono font-bold break-all">
                              {cd.httpWeakContainer.protocols.wireguard.endpoint}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Peer Public Key</span>
                            <span className="text-slate-300 font-mono text-[11px] break-all">
                              {cd.httpWeakContainer.protocols.wireguard.peerPublicKey}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Interface Address</span>
                            <span className="text-slate-200 font-mono">
                              {cd.httpWeakContainer.protocols.wireguard.address}
                            </span>
                          </div>
                          <div>
                            <span className="text-[10px] font-bold uppercase text-slate-400 block">Allowed IPs</span>
                            <span className="text-indigo-300 font-mono text-[11px]">
                              {cd.httpWeakContainer.protocols.wireguard.allowedIps}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Security Locks & Carrier Codes Matrix */}
                  <div className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2.5">
                    <div className="flex items-center justify-between border-b border-slate-800/80 pb-2">
                      <span className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                        Hardware & Carrier Security Lock Matrix
                      </span>
                      <span className="text-[10px] font-mono text-slate-400">
                        Restrictions enforced by com.wyrhub.tun Dalvik core
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                      <div>
                        <div className="text-[11px] font-bold text-slate-400 mb-1">Allowed Provider / Carrier Codes (MCC/MNC):</div>
                        <div className="flex flex-wrap gap-1">
                          {cd.httpWeakContainer.restrictions.allowedCarrierCodes.map((code) => (
                            <span key={code} className="px-2 py-0.5 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-cyan-300">
                              {code}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] font-bold text-slate-400 mb-1">Blocked Applications (Anti-Sniffing):</div>
                        <div className="flex flex-wrap gap-1">
                          {cd.httpWeakContainer.restrictions.blockedApps.map((pkg) => (
                            <span key={pkg} className="px-2 py-0.5 rounded bg-rose-950/40 border border-rose-900/60 text-[10px] font-mono text-rose-300">
                              {pkg}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Raw Decoded JSON Accordion */}
                  {cd.httpWeakContainer.rawJson && (
                    <details className="group rounded-xl bg-slate-950/70 border border-slate-800 overflow-hidden text-xs">
                      <summary className="px-3.5 py-2.5 cursor-pointer font-semibold text-slate-400 hover:text-slate-200 flex items-center justify-between">
                        <span>View Raw Decoded HTTP Weak Profile JSON</span>
                        <span className="text-slate-500 group-open:rotate-180 transition">▼</span>
                      </summary>
                      <div className="p-3 border-t border-slate-800 bg-slate-950/90 space-y-2">
                        <div className="flex justify-end">
                          <button
                            type="button"
                            onClick={() => copyText('HTTP Weak JSON', cd.httpWeakContainer?.rawJson || '')}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 cursor-pointer"
                          >
                            {copiedKey === 'HTTP Weak JSON' ? 'Copied!' : 'Copy JSON'}
                          </button>
                        </div>
                        <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-60 leading-relaxed">
                          {cd.httpWeakContainer.rawJson}
                        </pre>
                      </div>
                    </details>
                  )}

                  {/* Live Verification Probing Box */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-violet-500/30 space-y-3">
                    <div>
                      <h4 className="text-xs font-bold uppercase tracking-wider text-violet-300 flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-violet-400" />
                        Live Verification Probe for HTTP Weak Profile
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Test connection probes against the verified endpoint <code className="text-violet-300">{cd.httpWeakContainer.protocols.openvpn.endpoint}</code> and proxy <code className="text-violet-300">{cd.httpWeakContainer.protocols.ssh.proxy.hosts[0]}</code>.
                      </p>
                    </div>

                    <div className="flex justify-end pt-1">
                      <button
                        type="button"
                        disabled={loading}
                        onClick={() => handleInspect()}
                        className="px-4 py-2 rounded-xl bg-gradient-to-r from-violet-500 to-indigo-600 text-white font-bold text-xs cursor-pointer hover:opacity-90 transition shadow-md shadow-violet-500/20"
                      >
                        Run Live Verification Probe for {cd.httpWeakContainer.profileName}
                      </button>
                    </div>
                  </div>
                </div>
              )}

              {/* ==================== DARK TUNNEL (.DARK / DARKTUNNEL://) MULTI-PROTOCOL INSPECTOR CARD ==================== */}
              {showDarkTunnelCard && cd.darkTunnelContainer && (
                <div className="bg-slate-900/80 border border-purple-500/40 rounded-2xl p-4 sm:p-5 space-y-4 shadow-xl shadow-purple-950/20">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-purple-400 shrink-0" />
                      <div className="min-w-0">
                        <h3 className="text-base font-bold text-white truncate max-w-full flex items-center gap-2 flex-wrap">
                          <span>Dark Tunnel Multi-Protocol Inspector</span>
                          <span className="text-xs font-normal text-purple-300 font-mono">
                            ({cd.darkTunnelContainer.profileName})
                          </span>
                        </h3>
                        <div className="text-[11px] font-mono text-slate-400">
                          {cd.darkTunnelContainer.packageName} • v{cd.darkTunnelContainer.versionName} (Build {cd.darkTunnelContainer.versionCode}) • <code className="text-purple-300/90">{cd.darkTunnelContainer.wireFormat}</code>
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/15 text-purple-300 border border-purple-500/30 whitespace-nowrap uppercase">
                        Primary: {cd.darkTunnelContainer.tunnelTypeName}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${cd.darkTunnelContainer.isClosed
                            ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                          }`}
                      >
                        {cd.darkTunnelContainer.isClosed ? 'Closed / Protected' : 'Open / Unclosed'}
                      </span>
                      {cd.darkTunnelContainer.isPasswordProtected && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-rose-500/15 text-rose-300 border border-rose-500/30">
                          Password Protected
                        </span>
                      )}
                      {cd.darkTunnelContainer.isHwidLocked && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-sky-500/15 text-sky-300 border border-sky-500/30">
                          {cd.darkTunnelContainer.hwidList.length} HWID Locked
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Security / Provider Lock Grid */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 text-xs bg-slate-950/60 p-3 rounded-xl border border-slate-800/80">
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 tracking-wider">Container State</span>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.darkTunnelContainer.isClosed ? 'text-amber-400' : 'text-emerald-400'}`}>
                        {cd.darkTunnelContainer.isClosed ? 'Closed Config' : 'Open Config'}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 tracking-wider">Root Lock</span>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.darkTunnelContainer.blockRoot ? 'text-rose-400' : 'text-slate-400'}`}>
                        {cd.darkTunnelContainer.blockRoot ? 'Block Root' : 'Allowed'}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 tracking-wider">PlayStore Lock</span>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.darkTunnelContainer.blockPlayStore ? 'text-amber-400' : 'text-slate-400'}`}>
                        {cd.darkTunnelContainer.blockPlayStore ? 'Enforced' : 'Unlocked'}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 tracking-wider">Password Guard</span>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.darkTunnelContainer.isPasswordProtected ? 'text-purple-400' : 'text-slate-400'}`}>
                        {cd.darkTunnelContainer.isPasswordProtected ? 'Protected' : 'No Password'}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 tracking-wider">HWID Protection</span>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.darkTunnelContainer.isHwidLocked ? 'text-sky-400' : 'text-slate-400'}`}>
                        {cd.darkTunnelContainer.isHwidLocked ? `${cd.darkTunnelContainer.hwidList.length} Device(s)` : 'None'}
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] uppercase text-slate-400 tracking-wider">Validity / Expiry</span>
                      <div className={`font-mono font-bold mt-0.5 truncate ${cd.darkTunnelContainer.isExpired ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {cd.darkTunnelContainer.isExpired ? 'Expired' : (cd.darkTunnelContainer.expireAt ? 'Valid' : 'Unlimited')}
                      </div>
                    </div>
                  </div>

                  {/* Notes / Banner Messages */}
                  {(cd.darkTunnelContainer.message || cd.darkTunnelContainer.connectedMessage) && (
                    <div className="p-3 bg-purple-950/20 border border-purple-800/40 rounded-xl space-y-1.5 text-xs">
                      {cd.darkTunnelContainer.message && (
                        <div className="flex items-start gap-2">
                          <span className="text-[10px] font-bold text-purple-400 uppercase tracking-wider shrink-0 mt-0.5">Author Note:</span>
                          <span className="font-mono text-purple-200 break-words">{cd.darkTunnelContainer.message}</span>
                        </div>
                      )}
                      {cd.darkTunnelContainer.connectedMessage && (
                        <div className="flex items-start gap-2">
                          <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider shrink-0 mt-0.5">Connected Banner:</span>
                          <span className="font-mono text-emerald-200 break-words">{cd.darkTunnelContainer.connectedMessage}</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Extracted Protocol Data */}
                  <div className="space-y-3">
                    {/* SSH Protocol Card */}
                    {cd.darkTunnelContainer.protocols.ssh && (
                      <div className="p-3.5 bg-slate-950/80 border border-cyan-800/40 rounded-xl space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-cyan-400" />
                            <span className="text-xs font-bold text-cyan-300 uppercase tracking-wider">SSH Core (libssh)</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => copyText('darkSsh', `${cd.darkTunnelContainer!.protocols.ssh!.host}:${cd.darkTunnelContainer!.protocols.ssh!.port}@${cd.darkTunnelContainer!.protocols.ssh!.username}:${cd.darkTunnelContainer!.protocols.ssh!.password || ''}`)}
                            className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 underline cursor-pointer"
                          >
                            {copiedKey === 'darkSsh' ? 'Copied SSH!' : 'Copy SSH Host:User'}
                          </button>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Host & Port</span>
                            <span className="font-mono text-white font-semibold">{cd.darkTunnelContainer.protocols.ssh.host}:{cd.darkTunnelContainer.protocols.ssh.port}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Username</span>
                            <span className="font-mono text-cyan-200">{cd.darkTunnelContainer.protocols.ssh.username || 'Not configured'}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Password</span>
                            <span className="font-mono text-cyan-200">{cd.darkTunnelContainer.protocols.ssh.password ? '••••••••' : 'None / Key'}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* SlowDNS / DNSTT Protocol Card */}
                    {cd.darkTunnelContainer.protocols.dnstt && (
                      <div className="p-3.5 bg-slate-950/80 border border-amber-800/40 rounded-xl space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-amber-400" />
                            <span className="text-xs font-bold text-amber-300 uppercase tracking-wider">SlowDNS (DNSTT / Turbotunnel)</span>
                          </div>
                          <button
                            type="button"
                            onClick={() => copyText('darkDnstt', `${cd.darkTunnelContainer!.protocols.dnstt!.nameserver} | ${cd.darkTunnelContainer!.protocols.dnstt!.pubkey}`)}
                            className="text-[11px] font-mono text-amber-400 hover:text-amber-300 underline cursor-pointer"
                          >
                            {copiedKey === 'darkDnstt' ? 'Copied DNSTT!' : 'Copy NS & PubKey'}
                          </button>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Nameserver Domain</span>
                            <span className="font-mono text-amber-200 font-semibold">{cd.darkTunnelContainer.protocols.dnstt.nameserver || 'None'}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Public Key (Curve25519)</span>
                            <span className="font-mono text-amber-200 break-all">{cd.darkTunnelContainer.protocols.dnstt.pubkey || 'None'}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800 sm:col-span-2">
                            <span className="text-[10px] text-slate-400 block">UDP DNS Resolver & Port</span>
                            <span className="font-mono text-slate-300">{cd.darkTunnelContainer.protocols.dnstt.dnsResolver}:{cd.darkTunnelContainer.protocols.dnstt.dnsPort}</span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* HTTP Inject / Proxy & Payload Card */}
                    {cd.darkTunnelContainer.protocols.inject && (
                      <div className="p-3.5 bg-slate-950/80 border border-emerald-800/40 rounded-xl space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-emerald-400" />
                            <span className="text-xs font-bold text-emerald-300 uppercase tracking-wider">
                              HTTP Inject / Proxy ({cd.darkTunnelContainer.protocols.inject.mode})
                            </span>
                          </div>
                          {cd.darkTunnelContainer.protocols.inject.payload && (
                            <button
                              type="button"
                              onClick={() => copyText('darkPayload', cd.darkTunnelContainer!.protocols.inject!.payload)}
                              className="text-[11px] font-mono text-emerald-400 hover:text-emerald-300 underline cursor-pointer"
                            >
                              {copiedKey === 'darkPayload' ? 'Copied Payload!' : 'Copy Payload Template'}
                            </button>
                          )}
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">SNI Host</span>
                            <span className="font-mono text-emerald-200">{cd.darkTunnelContainer.protocols.inject.sni || 'Direct (No SNI)'}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Remote Proxy</span>
                            <span className="font-mono text-emerald-200">
                              {cd.darkTunnelContainer.protocols.inject.proxyHost ? `${cd.darkTunnelContainer.protocols.inject.proxyHost}:${cd.darkTunnelContainer.protocols.inject.proxyPort}` : 'Direct'}
                            </span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Enhanced Payload</span>
                            <span className="font-mono text-emerald-200">{cd.darkTunnelContainer.protocols.inject.payloadEnhanced ? 'Active' : 'Standard'}</span>
                          </div>
                        </div>
                        {cd.darkTunnelContainer.protocols.inject.payload && (
                          <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block mb-1">Payload String</span>
                            <pre className="text-[11px] font-mono text-emerald-300 whitespace-pre-wrap break-all bg-black/40 p-2 rounded max-h-28 overflow-y-auto">
                              {cd.darkTunnelContainer.protocols.inject.payload}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* V2Ray / Xray Protocol Card */}
                    {cd.darkTunnelContainer.protocols.v2ray && (
                      <div className="p-3.5 bg-slate-950/80 border border-indigo-800/40 rounded-xl space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="w-2 h-2 rounded-full bg-indigo-400" />
                            <span className="text-xs font-bold text-indigo-300 uppercase tracking-wider">
                              V2Ray Core ({cd.darkTunnelContainer.protocols.v2ray.protocol.toUpperCase()})
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => copyText('darkV2ray', `${cd.darkTunnelContainer!.protocols.v2ray!.host}:${cd.darkTunnelContainer!.protocols.v2ray!.port}#${cd.darkTunnelContainer!.protocols.v2ray!.uuid}`)}
                            className="text-[11px] font-mono text-indigo-400 hover:text-indigo-300 underline cursor-pointer"
                          >
                            {copiedKey === 'darkV2ray' ? 'Copied V2Ray!' : 'Copy V2Ray Host:UUID'}
                          </button>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Target Server</span>
                            <span className="font-mono text-indigo-200 font-semibold">{cd.darkTunnelContainer.protocols.v2ray.host}:{cd.darkTunnelContainer.protocols.v2ray.port}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">UUID / User ID</span>
                            <span className="font-mono text-indigo-200 break-all">{cd.darkTunnelContainer.protocols.v2ray.uuid || 'None'}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Transport & Security</span>
                            <span className="font-mono text-indigo-200">{cd.darkTunnelContainer.protocols.v2ray.transport} + {cd.darkTunnelContainer.protocols.v2ray.tls ? 'TLS' : 'Plain'}</span>
                          </div>
                          {cd.darkTunnelContainer.protocols.v2ray.wsPath && (
                            <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800 sm:col-span-2">
                              <span className="text-[10px] text-slate-400 block">WebSocket Path & Host</span>
                              <span className="font-mono text-indigo-200">{cd.darkTunnelContainer.protocols.v2ray.wsPath} ({cd.darkTunnelContainer.protocols.v2ray.wsHost || 'Default'})</span>
                            </div>
                          )}
                          {cd.darkTunnelContainer.protocols.v2ray.sni && (
                            <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                              <span className="text-[10px] text-slate-400 block">Server Name Indication (SNI)</span>
                              <span className="font-mono text-indigo-200">{cd.darkTunnelContainer.protocols.v2ray.sni}</span>
                            </div>
                          )}
                        </div>
                        {cd.darkTunnelContainer.protocols.v2ray.customConfigJson && (
                          <div className="bg-slate-900/90 p-2.5 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block mb-1">Custom V2Ray Configuration JSON</span>
                            <pre className="text-[11px] font-mono text-indigo-300 whitespace-pre-wrap break-all bg-black/40 p-2 rounded max-h-32 overflow-y-auto">
                              {cd.darkTunnelContainer.protocols.v2ray.customConfigJson}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* OpenVPN Core Card */}
                    {cd.darkTunnelContainer.protocols.openvpn && (
                      <div className="p-3.5 bg-slate-950/80 border border-teal-800/40 rounded-xl space-y-2">
                        <div className="flex items-center gap-2">
                          <span className="w-2 h-2 rounded-full bg-teal-400" />
                          <span className="text-xs font-bold text-teal-300 uppercase tracking-wider">OpenVPN Core</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Server Host & Port</span>
                            <span className="font-mono text-teal-200 font-semibold">{cd.darkTunnelContainer.protocols.openvpn.host}:{cd.darkTunnelContainer.protocols.openvpn.port}</span>
                          </div>
                          <div className="bg-slate-900/90 p-2 rounded-lg border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">User Credentials</span>
                            <span className="font-mono text-teal-200">{cd.darkTunnelContainer.protocols.openvpn.username} : {cd.darkTunnelContainer.protocols.openvpn.password ? '••••••' : 'None'}</span>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Dark Tunnel Cloud & Telegram Updates */}
                  <div className="p-3.5 bg-gradient-to-r from-purple-950/40 via-indigo-950/30 to-slate-950/40 border border-purple-800/40 rounded-xl text-xs space-y-2">
                    <div className="flex items-center justify-between flex-wrap gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-purple-400 font-bold">☁️ Dark Tunnel Cloud System</span>
                        <span className="text-[10px] text-slate-400 font-mono">Telegram Official Channels & Config Updates</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <a
                          href={cd.darkTunnelContainer.cloud.channelUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2.5 py-1 rounded-lg bg-purple-600/30 hover:bg-purple-600/50 text-purple-200 border border-purple-500/40 text-[11px] font-semibold transition"
                        >
                          Channel @darktunnel_app
                        </a>
                        <a
                          href={cd.darkTunnelContainer.cloud.groupUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="px-2.5 py-1 rounded-lg bg-indigo-600/30 hover:bg-indigo-600/50 text-indigo-200 border border-indigo-500/40 text-[11px] font-semibold transition"
                        >
                          Group @darktunnel_app_group
                        </a>
                      </div>
                    </div>
                  </div>

                  {/* Raw Dark Tunnel JSON */}
                  {cd.darkTunnelContainer.rawJson && (
                    <div className="space-y-1.5 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                          Full Dark Tunnel JSON Inspection
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText('darkRawJson', cd.darkTunnelContainer?.rawJson || '')}
                          className="text-[11px] font-mono text-purple-400 hover:text-purple-300 underline cursor-pointer"
                        >
                          {copiedKey === 'darkRawJson' ? 'Copied JSON!' : 'Copy Dark Tunnel JSON'}
                        </button>
                      </div>
                      <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap break-all bg-slate-950 p-3 rounded-xl border border-slate-800 max-h-48 overflow-y-auto">
                        {cd.darkTunnelContainer.rawJson}
                      </pre>
                    </div>
                  )}

                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      disabled={loading}
                      onClick={() => handleInspect()}
                      className="px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-bold text-xs cursor-pointer hover:opacity-90 transition shadow-md shadow-purple-500/20"
                    >
                      Run Live Verification Probe for {cd.darkTunnelContainer.profileName}
                    </button>
                  </div>
                </div>
              )}

              {/* ==================== HA TUNNEL PLUS (.HAT / TNJL) SEALED ENVELOPE INSPECTOR CARD ==================== */}
              {showHaTunnelCard && cd.haTunnelContainer && (
                <div className="bg-slate-900/75 border border-amber-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        HA Tunnel Plus Locked Config (<code className="text-amber-300 break-all">{cd.haTunnelContainer.profileName}</code>)
                      </h3>
                    </div>
                    <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                      <button
                        type="button"
                        onClick={() => copyText('hatSni', cd.haTunnelContainer!.sni)}
                        className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 cursor-pointer"
                      >
                        {copiedKey === 'hatSni' ? 'Copied SNI!' : 'Copy SNI'}
                      </button>
                      <button
                        type="button"
                        onClick={() => copyText('hatPayload', cd.haTunnelContainer!.proxyPayload)}
                        className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/30 cursor-pointer"
                      >
                        {copiedKey === 'hatPayload' ? 'Copied Payload!' : 'Copy Payload'}
                      </button>
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30 whitespace-nowrap">
                        {cd.haTunnelContainer.magic} LOCKED ENVELOPE
                      </span>
                    </div>
                  </div>

                  {/* Envelope Metadata Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {[
                      { label: 'Profile Name', value: cd.haTunnelContainer.profileName },
                      { label: 'Client Application', value: `${cd.haTunnelContainer.appName} (${cd.haTunnelContainer.clientPackage})` },
                      { label: 'Target Carrier / Network', value: cd.haTunnelContainer.targetCarrier },
                      { label: 'Connection Mode', value: `${cd.haTunnelContainer.tunnelMode} [Mode #${cd.haTunnelContainer.tunnelModeId}]` },
                      { label: 'SNI (Server Name Indication)', value: cd.haTunnelContainer.sni },
                      { label: 'Outbound Relay Server', value: `${cd.haTunnelContainer.serverHost}:${cd.haTunnelContainer.serverPort}` },
                      { label: 'Wire Specification', value: cd.haTunnelContainer.wireFormat },
                      { label: 'Envelope Payload', value: `${cd.haTunnelContainer.payloadLength.toLocaleString()} bytes (Base64 Enclosed)` },
                      { label: 'Profile Expiration', value: cd.haTunnelContainer.expiryDate },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-amber-300/90">
                            {item.label}
                          </div>
                          <div className="text-sm font-mono text-slate-100 truncate mt-0.5" title={item.value}>
                            {item.value}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyText(item.label, item.value)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                        >
                          {copiedKey === item.label ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    ))}
                  </div>

                  {/* Security Matrix Badges */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      HA Tunnel Plus Security & Hardware Enforcement Matrix
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 text-xs">
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Root Guard:</span>
                        <span className="font-mono font-bold text-emerald-400">Blocked</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Play Store:</span>
                        <span className="font-mono font-bold text-cyan-400">Enforced</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">HWID Lock:</span>
                        <span className="font-mono font-bold text-amber-400">Bound</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Anti-Torrent:</span>
                        <span className="font-mono font-bold text-rose-400">Filtered</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Password:</span>
                        <span className="font-mono font-bold text-slate-400">None</span>
                      </div>
                    </div>
                  </div>

                  {/* Custom SNI & HTTP Injection Payload */}
                  {cd.haTunnelContainer.proxyPayload && (
                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-amber-500/30 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider text-amber-400">
                          Verified HTTP Injection Template & Spoofing Payload
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText('hatPayloadBox', cd.haTunnelContainer!.proxyPayload)}
                          className="text-xs text-cyan-400 hover:underline cursor-pointer"
                        >
                          {copiedKey === 'hatPayloadBox' ? 'Copied Payload!' : 'Copy Payload'}
                        </button>
                      </div>
                      <pre className="font-mono text-xs text-amber-200/90 whitespace-pre-wrap bg-slate-900 p-2.5 rounded-lg border border-slate-800 select-all">
                        {cd.haTunnelContainer.proxyPayload}
                      </pre>
                    </div>
                  )}

                  {/* Cloud Infrastructure & Server Cluster */}
                  <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-bold uppercase text-[10px]">
                        Cloud Relay Network
                      </span>
                      <span className="text-slate-300">{cd.haTunnelContainer.cloudServers}</span>
                    </div>
                    <span className="text-slate-400 font-mono text-[11px]">Art Of Tunnel Cloud v118</span>
                  </div>

                  {/* Raw Envelope Hex Preview */}
                  {cd.haTunnelContainer.rawEnvelopeHexPreview && (
                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                          Ciphertext Container Envelope Preview (First 32 Decoded Bytes)
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText('hatHex', cd.haTunnelContainer!.rawEnvelopeHexPreview)}
                          className="text-xs text-cyan-400 hover:underline cursor-pointer"
                        >
                          {copiedKey === 'hatHex' ? 'Copied Hex!' : 'Copy Hex'}
                        </button>
                      </div>
                      <div className="font-mono text-xs text-amber-300/80 break-all bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                        {cd.haTunnelContainer.rawEnvelopeHexPreview}
                      </div>
                    </div>
                  )}

                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      disabled={loading}
                      onClick={() => handleInspect()}
                      className="px-4 py-2 rounded-xl bg-gradient-to-r from-amber-600 to-yellow-600 text-white font-bold text-xs cursor-pointer hover:opacity-90 transition shadow-md shadow-amber-500/20"
                    >
                      Run Live Verification Probe for {cd.haTunnelContainer.profileName}
                    </button>
                  </div>
                </div>
              )}

              
              {/* ==================== NETMOD SYNA (.NM / NM://) MULTI-PROFILE & TUNNEL INSPECTOR CARD ==================== */}
              {showNetmodCard && cd.netmodContainer && (
                <div className="bg-slate-900/80 border border-sky-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  {/* Header */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-sky-400 shrink-0 shadow-sm shadow-sky-400/50" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        NetMod Syna Engine (<code className="text-sky-300 break-all">{cd.netmodContainer.appName}</code>)
                      </h3>
                      <span className="text-[11px] font-mono text-sky-300/90 bg-sky-950/50 border border-sky-800/60 px-2 py-0.5 rounded-md">
                        {cd.netmodContainer.packageName} • {cd.netmodContainer.isWindowsVer ? 'Windows' : `Android API v${cd.netmodContainer.versionAndroid || 16}`}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap shrink-0">
                      {cd.netmodContainer.profiles.length > 0 && cd.netmodContainer.profiles[0].shareUri && (
                        <button
                          type="button"
                          onClick={() => copyText('netmodShare', cd.netmodContainer!.profiles[0].shareUri || '')}
                          className="px-2.5 py-1 rounded-lg bg-sky-500/15 text-sky-300 hover:bg-sky-500/25 text-xs font-semibold border border-sky-500/30 cursor-pointer transition"
                        >
                          {copiedKey === 'netmodShare' ? 'Copied URI!' : 'Copy Share URI'}
                        </button>
                      )}
                      {cd.netmodContainer.profiles.length > 0 && (
                        <button
                          type="button"
                          onClick={() => copyText('netmodHost', `${cd.netmodContainer!.profiles[0].hostname}:${cd.netmodContainer!.profiles[0].port}`)}
                          className="px-2.5 py-1 rounded-lg bg-indigo-500/15 text-indigo-300 hover:bg-indigo-500/25 text-xs font-semibold border border-indigo-500/30 cursor-pointer transition"
                        >
                          {copiedKey === 'netmodHost' ? 'Copied Host!' : 'Copy Host:Port'}
                        </button>
                      )}
                      <span className="px-2.5 py-1 rounded-lg bg-sky-950/60 text-sky-300 border border-sky-800/60 text-xs font-bold uppercase tracking-wider">
                        {cd.netmodContainer.profileCount > 0 ? `${cd.netmodContainer.profileCount} Profile${cd.netmodContainer.profileCount > 1 ? 's' : ''}` : cd.netmodContainer.tunnelConfig?.modeName || 'Tunnel Mode'}
                      </span>
                      <span
                        className={`px-2.5 py-1 rounded-lg text-xs font-bold border ${
                          cd.netmodContainer.preventRoot || cd.netmodContainer.hwIds.length > 0
                            ? 'bg-amber-950/40 text-amber-300 border-amber-800/50'
                            : 'bg-emerald-950/40 text-emerald-300 border-emerald-800/50'
                        }`}
                      >
                        {cd.netmodContainer.preventRoot ? 'Root Protected' : (cd.netmodContainer.hwIds.length > 0 ? 'HWID Locked' : 'Unlocked')}
                      </span>
                    </div>
                  </div>

                  {/* Note Banner if present */}
                  {cd.netmodContainer.note && (
                    <div className="bg-sky-950/30 border border-sky-800/40 rounded-xl p-3 text-xs text-sky-200">
                      <span className="font-bold text-sky-400 mr-2">Config Note:</span>
                      <span>{cd.netmodContainer.note}</span>
                    </div>
                  )}

                  {/* Cryptographic Security & Protection Matrix */}
                  <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 sm:p-4 space-y-2.5">
                    <div className="flex items-center justify-between text-xs font-bold text-slate-300">
                      <span className="flex items-center gap-1.5">
                        <span className="w-2 h-2 rounded-full bg-sky-400"></span>
                        NetMod Cryptographic Security & Hardware Protection Matrix
                      </span>
                      <span className="text-[11px] font-mono text-sky-400">
                        {cd.netmodContainer.cipher} {cd.netmodContainer.keyIndexUsed !== undefined ? `(Eichgee Master Key #${cd.netmodContainer.keyIndexUsed + 1})` : ''}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
                        <span className="text-slate-400 text-[10px] uppercase font-bold block">Root Protection</span>
                        <span className={`font-mono font-bold mt-0.5 block ${cd.netmodContainer.preventRoot ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {cd.netmodContainer.preventRoot ? 'Active (Block Root)' : 'Off (Allowed)'}
                        </span>
                      </div>
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
                        <span className="text-slate-400 text-[10px] uppercase font-bold block">WiFi Restriction</span>
                        <span className={`font-mono font-bold mt-0.5 block ${cd.netmodContainer.preventWifi ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {cd.netmodContainer.preventWifi ? 'Active (Mobile Only)' : 'Off (Any Network)'}
                        </span>
                      </div>
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
                        <span className="text-slate-400 text-[10px] uppercase font-bold block">HWID Device Binding</span>
                        <span className={`font-mono font-bold mt-0.5 block ${cd.netmodContainer.hwIds.length > 0 ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {cd.netmodContainer.hwIds.length > 0 ? `${cd.netmodContainer.hwIds.length} Bound Device(s)` : 'Any Device (Unlocked)'}
                        </span>
                      </div>
                      <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
                        <span className="text-slate-400 text-[10px] uppercase font-bold block">Config Expiration</span>
                        <span className={`font-mono font-bold mt-0.5 block ${cd.netmodContainer.isExpired ? 'text-rose-400' : (cd.netmodContainer.expire ? 'text-emerald-400' : 'text-slate-400')}`}>
                          {cd.netmodContainer.expire || 'No Expiration Set'}
                        </span>
                      </div>
                    </div>

                    {cd.netmodContainer.hwIds.length > 0 && (
                      <div className="bg-slate-900/80 border border-amber-900/40 rounded-lg p-2.5 mt-2">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-amber-300 block mb-1">
                          Locked Hardware Fingerprints ({cd.netmodContainer.hwIds.length})
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {cd.netmodContainer.hwIds.map((hw, idx) => (
                            <code key={idx} className="bg-amber-950/40 border border-amber-800/50 text-amber-200 text-[11px] font-mono px-2 py-0.5 rounded">
                              {hw}
                            </code>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Multi-Profiles List */}
                  {cd.netmodContainer.profiles.length > 0 && (
                    <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 sm:p-4 space-y-3">
                      <div className="flex items-center justify-between text-xs font-bold text-slate-300">
                        <span className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-indigo-400"></span>
                          NetMod Multi-Protocol Profiles ({cd.netmodContainer.profiles.length})
                        </span>
                        <span className="text-[11px] font-mono text-indigo-400">
                          {cd.netmodContainer.supportedProtocols.join(' • ')}
                        </span>
                      </div>

                      <div className="space-y-2.5">
                        {cd.netmodContainer.profiles.map((p, idx) => (
                          <div key={idx} className="bg-slate-900/75 border border-slate-800/80 hover:border-sky-500/30 rounded-xl p-3 transition space-y-2">
                            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                              <div className="flex items-center gap-2">
                                <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-sky-950/70 text-sky-300 border border-sky-800/60">
                                  {p.protocol}
                                </span>
                                <span className="font-bold text-white text-xs">
                                  {p.remark || `Profile #${idx + 1}`}
                                </span>
                                {p.locked && (
                                  <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-amber-950/60 text-amber-400 border border-amber-800/50">
                                    LOCKED
                                  </span>
                                )}
                              </div>
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-xs text-sky-300 font-semibold">
                                  {p.hostname}:{p.port}
                                </span>
                                {p.shareUri && (
                                  <button
                                    type="button"
                                    onClick={() => copyText(`pShare${idx}`, p.shareUri || '')}
                                    className="px-2 py-0.5 rounded bg-sky-500/10 text-sky-300 hover:bg-sky-500/20 text-[10px] font-semibold border border-sky-500/30 cursor-pointer transition"
                                  >
                                    {copiedKey === `pShare${idx}` ? 'Copied!' : 'Copy Link'}
                                  </button>
                                )}
                              </div>
                            </div>

                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
                              <div>
                                <span className="text-slate-500 text-[10px] uppercase block">Transport / Network</span>
                                <span className="font-mono text-slate-200 font-semibold">
                                  {(p.transferProtocol || 'tcp').toUpperCase()} {p.tlsType ? `(${p.tlsType.toUpperCase()})` : ''}
                                </span>
                              </div>
                              <div>
                                <span className="text-slate-500 text-[10px] uppercase block">SNI / Host Header</span>
                                <span className="font-mono text-sky-200 font-semibold truncate block">
                                  {p.sni || p.host || 'None'}
                                </span>
                              </div>
                              <div>
                                <span className="text-slate-500 text-[10px] uppercase block">WebSocket Path</span>
                                <span className="font-mono text-indigo-300 font-semibold truncate block">
                                  {p.path || '/'}
                                </span>
                              </div>
                              <div>
                                <span className="text-slate-500 text-[10px] uppercase block">Auth / User ID</span>
                                <span className="font-mono text-slate-300 truncate block">
                                  {p.userId || p.password || 'None'}
                                </span>
                              </div>
                            </div>

                            {(p.pubKey || p.shortId || p.fingerprint || p.alpn) && (
                              <div className="bg-slate-950/50 rounded-lg p-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] font-mono border border-slate-800/50">
                                {p.pubKey && (
                                  <span className="text-amber-300 truncate max-w-[240px]">
                                    <strong className="text-slate-400">PubKey:</strong> {p.pubKey}
                                  </span>
                                )}
                                {p.shortId && (
                                  <span className="text-amber-300">
                                    <strong className="text-slate-400">ShortId:</strong> {p.shortId}
                                  </span>
                                )}
                                {p.fingerprint && (
                                  <span className="text-cyan-300">
                                    <strong className="text-slate-400">FP:</strong> {p.fingerprint}
                                  </span>
                                )}
                                {p.alpn && (
                                  <span className="text-emerald-300">
                                    <strong className="text-slate-400">ALPN:</strong> {p.alpn}
                                  </span>
                                )}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Single Tunnel Config (Direct / SSH / HTTP Custom / WireGuard) */}
                  {cd.netmodContainer.tunnelConfig && (
                    <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 sm:p-4 space-y-3">
                      <div className="flex items-center justify-between text-xs font-bold text-slate-300">
                        <span className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
                          NetMod Tunnel Configuration ({cd.netmodContainer.tunnelConfig.modeName})
                        </span>
                        <span className="text-[11px] font-mono text-emerald-400">
                          Mode {cd.netmodContainer.tunnelConfig.mode}
                        </span>
                      </div>

                      {cd.netmodContainer.tunnelConfig.payload && (
                        <div className="space-y-1">
                          <div className="flex items-center justify-between">
                            <span className="text-[10px] uppercase font-bold text-slate-400">
                              HTTP Custom / Injector Payload {cd.netmodContainer.tunnelConfig.payloadLocked ? '(LOCKED)' : ''}
                            </span>
                            <button
                              type="button"
                              onClick={() => copyText('netmodPayload', cd.netmodContainer!.tunnelConfig!.payload || '')}
                              className="text-[10px] text-sky-400 hover:text-sky-300"
                            >
                              {copiedKey === 'netmodPayload' ? 'Copied' : 'Copy Payload'}
                            </button>
                          </div>
                          <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-300 whitespace-pre-wrap break-all max-h-28 overflow-y-auto">
                            {cd.netmodContainer.tunnelConfig.payload}
                          </pre>
                        </div>
                      )}

                      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                        {cd.netmodContainer.tunnelConfig.sni && (
                          <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
                            <span className="text-slate-400 text-[10px] uppercase font-bold block">
                              SSL Spoof / SNI {cd.netmodContainer.tunnelConfig.sniLocked ? '(Locked)' : ''}
                            </span>
                            <span className="font-mono text-sky-300 font-semibold truncate block mt-0.5">
                              {cd.netmodContainer.tunnelConfig.sni}
                            </span>
                          </div>
                        )}
                        {cd.netmodContainer.tunnelConfig.proxy && (
                          <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
                            <span className="text-slate-400 text-[10px] uppercase font-bold block">
                              Remote Proxy {cd.netmodContainer.tunnelConfig.proxyLocked ? '(Locked)' : ''}
                            </span>
                            <span className="font-mono text-amber-300 font-semibold truncate block mt-0.5">
                              {cd.netmodContainer.tunnelConfig.proxy}
                            </span>
                          </div>
                        )}
                        {cd.netmodContainer.tunnelConfig.ssh && (
                          <div className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5">
                            <span className="text-slate-400 text-[10px] uppercase font-bold block">
                              SSH Endpoint {cd.netmodContainer.tunnelConfig.sshLocked ? '(Locked)' : ''}
                            </span>
                            <span className="font-mono text-indigo-300 font-semibold truncate block mt-0.5">
                              {cd.netmodContainer.tunnelConfig.ssh}
                            </span>
                          </div>
                        )}
                      </div>

                      {cd.netmodContainer.tunnelConfig.peerPublicKey && (
                        <div className="bg-slate-900/80 border border-indigo-900/40 rounded-lg p-2.5 space-y-1 text-[11px] font-mono">
                          <span className="text-[10px] uppercase font-bold text-indigo-300 block">WireGuard Tunnel Configuration</span>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-slate-300">
                            <div><strong className="text-slate-500">Peer:</strong> {cd.netmodContainer.tunnelConfig.peerEndpoint}</div>
                            <div><strong className="text-slate-500">Address:</strong> {cd.netmodContainer.tunnelConfig.interfaceAddress || '10.0.0.2/32'}</div>
                            <div className="truncate"><strong className="text-slate-500">Peer Key:</strong> {cd.netmodContainer.tunnelConfig.peerPublicKey}</div>
                            <div className="truncate"><strong className="text-slate-500">Priv Key:</strong> {cd.netmodContainer.tunnelConfig.interfacePrivateKey || 'Protected'}</div>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Server Groups / Cloud Subscriptions */}
                  {((cd.netmodContainer.serverGroups && cd.netmodContainer.serverGroups.length > 0) || cd.netmodContainer.cloud.hasCloud) && (
                    <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 sm:p-4 space-y-2.5">
                      <div className="flex items-center justify-between text-xs font-bold text-slate-300">
                        <span className="flex items-center gap-1.5">
                          <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                          NetMod Cloud Server Groups & Subscriptions
                        </span>
                        <span className="text-[11px] font-mono text-cyan-400">
                          {cd.netmodContainer.serverGroups?.length || 0} Group(s)
                        </span>
                      </div>

                      {cd.netmodContainer.serverGroups && cd.netmodContainer.serverGroups.map((grp, gIdx) => (
                        <div key={gIdx} className="bg-slate-900/70 border border-slate-800 rounded-lg p-2.5 flex flex-wrap items-center justify-between gap-2 text-xs">
                          <div>
                            <span className="font-bold text-white block">{grp.name}</span>
                            <span className="font-mono text-[11px] text-cyan-300 break-all">{grp.url}</span>
                          </div>
                          {grp.url && (
                            <button
                              type="button"
                              onClick={() => copyText(`grpUrl${gIdx}`, grp.url)}
                              className="px-2 py-1 rounded bg-cyan-500/10 text-cyan-300 hover:bg-cyan-500/20 text-[10px] font-semibold border border-cyan-500/30 cursor-pointer transition"
                            >
                              {copiedKey === `grpUrl${gIdx}` ? 'Copied' : 'Copy URL'}
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Raw Decrypted JSON View */}
                  {cd.netmodContainer.rawDecryptedJson && (
                    <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-3 sm:p-4 space-y-2">
                      <div className="flex items-center justify-between text-xs font-bold text-slate-300">
                        <span>NetMod Decrypted Configuration JSON</span>
                        <button
                          type="button"
                          onClick={() => copyText('netmodJson', cd.netmodContainer!.rawDecryptedJson!)}
                          className="px-2.5 py-1 rounded-lg bg-sky-500/15 text-sky-300 hover:bg-sky-500/25 text-[10px] font-semibold border border-sky-500/30 cursor-pointer transition"
                        >
                          {copiedKey === 'netmodJson' ? 'Copied JSON!' : 'Copy Decrypted JSON'}
                        </button>
                      </div>
                      <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-sky-200 whitespace-pre max-h-48 overflow-auto">
                        {cd.netmodContainer.rawDecryptedJson}
                      </pre>
                    </div>
                  )}

                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      disabled={loading}
                      onClick={() => handleInspect()}
                      className="px-4 py-2 rounded-xl bg-gradient-to-r from-sky-600 to-indigo-600 text-white font-bold text-xs cursor-pointer hover:opacity-90 transition shadow-md shadow-sky-500/20"
                    >
                      Run Live Verification Probe for {cd.netmodContainer.appName}
                    </button>
                  </div>
                </div>
              )}

              {/* ==================== V2BOX (.V2BOX / V2BOX://) MULTI-PROTOCOL & CLOUD INSPECTOR CARD ==================== */}
              {showV2BoxCard && cd.v2boxContainer && (
                <div className="bg-slate-900/75 border border-cyan-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        V2Box Multi-Protocol Engine (<code className="text-cyan-300 break-all">{cd.v2boxContainer.profileName}</code>)
                      </h3>
                      <span className="text-[11px] font-mono text-cyan-300/80 bg-cyan-950/40 border border-cyan-800/50 px-2 py-0.5 rounded-md">
                        {cd.v2boxContainer.packageName} • v{cd.v2boxContainer.version}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 flex-wrap sm:flex-nowrap shrink-0">
                      <button
                        type="button"
                        onClick={() => copyText('v2boxShare', cd.v2boxContainer!.shareLink || '')}
                        className="px-2.5 py-1 rounded-lg bg-cyan-500/15 text-cyan-300 hover:bg-cyan-500/25 text-xs font-semibold border border-cyan-500/30 cursor-pointer transition"
                      >
                        {copiedKey === 'v2boxShare' ? 'Copied Share Link!' : 'Copy Share Link'}
                      </button>
                      <button
                        type="button"
                        onClick={() => copyText('v2boxEndpoint', `${cd.v2boxContainer!.outboundServer}:${cd.v2boxContainer!.outboundPort}`)}
                        className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 cursor-pointer transition"
                      >
                        {copiedKey === 'v2boxEndpoint' ? 'Copied Host:Port!' : 'Copy Server'}
                      </button>
                      <span className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-[10px] font-bold uppercase tracking-wider border border-cyan-500/40">
                        {cd.v2boxContainer.activeProtocol}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          cd.v2boxContainer.isDeviceLocked || cd.v2boxContainer.isPasswordProtected
                            ? 'bg-amber-500/15 text-amber-300 border border-amber-500/30'
                            : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                        }`}
                      >
                        {cd.v2boxContainer.isDeviceLocked ? 'Hardware Locked' : (cd.v2boxContainer.isPasswordProtected ? 'Password Locked' : 'Unlocked Profile')}
                      </span>
                    </div>
                  </div>

                  {/* V2Box Core Profile Specifications Grid */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5 text-xs">
                    <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Wire Specification</span>
                      <span className="font-mono text-cyan-200 font-semibold break-words mt-0.5 block">{cd.v2boxContainer.wireFormat}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Primary Outbound</span>
                      <span className="font-mono text-cyan-200 font-semibold truncate mt-0.5 block">{cd.v2boxContainer.outboundServer}:{cd.v2boxContainer.outboundPort}</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Transport & Security</span>
                      <span className="font-mono text-cyan-200 font-semibold truncate mt-0.5 block">
                        {cd.v2boxContainer.transport?.toUpperCase() || 'TCP'} • {cd.v2boxContainer.security?.toUpperCase() || 'TLS'}
                      </span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800">
                      <span className="text-slate-400 block text-[10px] uppercase font-bold tracking-wider">Profile Expiration</span>
                      <span className={`font-mono font-semibold truncate mt-0.5 block ${cd.v2boxContainer.isExpired ? 'text-rose-400' : 'text-emerald-300'}`}>
                        {cd.v2boxContainer.expirationFormatted}
                      </span>
                    </div>
                  </div>

                  {/* Security Matrix Badges */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center justify-between">
                      <span>V2Box Cryptographic Security & Hardware Protection Matrix</span>
                      <span className="text-[11px] font-mono text-cyan-400">{cd.v2boxContainer.cipher}</span>
                    </div>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Device Binding:</span>
                        <span className={`font-mono font-bold ${cd.v2boxContainer.isDeviceLocked ? 'text-amber-400' : 'text-emerald-400'}`}>
                          {cd.v2boxContainer.isDeviceLocked ? `${cd.v2boxContainer.allowedDeviceIDs.length} Device(s)` : 'Any Device'}
                        </span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Key Derivation:</span>
                        <span className="font-mono font-bold text-cyan-300 truncate max-w-[120px]" title={cd.v2boxContainer.keyDerivation}>
                          {cd.v2boxContainer.keyDerivation.split('/')[0].trim()}
                        </span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Password Guard:</span>
                        <span className={`font-mono font-bold ${cd.v2boxContainer.isPasswordProtected ? 'text-amber-400' : 'text-slate-400'}`}>
                          {cd.v2boxContainer.isPasswordProtected ? 'Protected' : 'None'}
                        </span>
                      </div>
                      <div className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-400">Core Runtime:</span>
                        <span className="font-mono font-bold text-indigo-400">LibXray Lite</span>
                      </div>
                    </div>

                    {cd.v2boxContainer.allowedDeviceIDs.length > 0 && (
                      <div className="pt-1">
                        <span className="text-[11px] text-slate-400">Authorized Device UUIDs:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {cd.v2boxContainer.allowedDeviceIDs.map((hw, idx) => (
                            <span key={idx} className="font-mono text-[10px] bg-slate-900 text-amber-300 px-2 py-0.5 rounded border border-slate-800">
                              {hw}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Cloud Subscriptions & WebDAV Cloud Sync */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-cyan-500/30 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full bg-cyan-400"></span>
                        <span className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                          V2Box Cloud Subscriptions & WebDAV Cloud Integration
                        </span>
                      </div>
                      <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                        {cd.v2boxContainer.cloud.hasCloud ? 'Cloud Enabled' : 'Local / Offline Sync'}
                      </span>
                    </div>

                    {cd.v2boxContainer.cloud.subscriptionUrl ? (
                      <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-[11px] font-semibold text-slate-300">Remote Cloud Subscription URL:</span>
                          <button
                            type="button"
                            onClick={() => copyText('v2boxSubUrl', cd.v2boxContainer!.cloud.subscriptionUrl!)}
                            className="text-[11px] text-cyan-400 hover:underline cursor-pointer"
                          >
                            {copiedKey === 'v2boxSubUrl' ? 'Copied URL!' : 'Copy Subscription Link'}
                          </button>
                        </div>
                        <div className="font-mono text-xs text-cyan-200/90 break-all bg-slate-950 p-2 rounded border border-slate-800/80">
                          {cd.v2boxContainer.cloud.subscriptionUrl}
                        </div>
                        <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
                          <span>Auto-Update Sync: <strong className="text-emerald-400">{cd.v2boxContainer.cloud.autoUpdate ? `Enabled (${cd.v2boxContainer.cloud.updateIntervalHours}h interval)` : 'Manual'}</strong></span>
                          <span>Cloud API: <span className="font-mono text-slate-300">{cd.v2boxContainer.cloud.apiServer.split('/')[0].trim()}</span></span>
                        </div>
                      </div>
                    ) : null}

                    {cd.v2boxContainer.cloud.webDavConfig?.enabled ? (
                      <div className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 space-y-1.5">
                        <span className="text-[11px] font-semibold text-slate-300 block">WebDAV Cloud Backup & Configuration Restore:</span>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs">
                          <div className="p-1.5 rounded bg-slate-950 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Endpoint Base URL</span>
                            <span className="font-mono text-cyan-300 break-all">{cd.v2boxContainer.cloud.webDavConfig.baseUrl}</span>
                          </div>
                          <div className="p-1.5 rounded bg-slate-950 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Remote Cloud Path</span>
                            <span className="font-mono text-cyan-300">{cd.v2boxContainer.cloud.webDavConfig.remoteBasePath}</span>
                          </div>
                          <div className="p-1.5 rounded bg-slate-950 border border-slate-800">
                            <span className="text-[10px] text-slate-400 block">Timeout</span>
                            <span className="font-mono text-cyan-300">{cd.v2boxContainer.cloud.webDavConfig.timeoutSeconds}s</span>
                          </div>
                        </div>
                      </div>
                    ) : null}

                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs pt-1">
                      <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Cloud Upload</span>
                        <span className="font-mono text-slate-200 font-semibold">{cd.v2boxContainer.cloud.userInfo?.upload || '0.00 GB'}</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Cloud Download</span>
                        <span className="font-mono text-slate-200 font-semibold">{cd.v2boxContainer.cloud.userInfo?.download || '0.00 GB'}</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Total Quota</span>
                        <span className="font-mono text-cyan-300 font-semibold">{cd.v2boxContainer.cloud.userInfo?.total || 'Unlimited'}</span>
                      </div>
                      <div className="p-2 rounded bg-slate-900/90 border border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Quota Valid Until</span>
                        <span className="font-mono text-emerald-300 font-semibold">{cd.v2boxContainer.cloud.userInfo?.expire || 'Permanent'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Chaining Hops (if chain://) */}
                  {cd.v2boxContainer.chainingHops && cd.v2boxContainer.chainingHops.length > 0 && (
                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-indigo-500/30 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
                          V2Box Proxy Chaining Pipeline ({cd.v2boxContainer.chainingHops.length} Hops)
                        </span>
                        <span className="text-[10px] font-mono text-indigo-400">Multi-Hop Routing</span>
                      </div>
                      <div className="space-y-1.5">
                        {cd.v2boxContainer.chainingHops.map((hop, hIdx) => (
                          <div key={hIdx} className="flex items-center gap-2 p-2 rounded bg-slate-900 border border-slate-800 text-xs">
                            <span className="px-1.5 py-0.5 rounded bg-indigo-500/20 text-indigo-300 font-bold text-[10px]">Hop #{hIdx + 1}</span>
                            <span className="font-mono text-slate-200 break-all">{hop}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Active Protocol Network Pipeline Details */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      Active Outbound Network Pipeline & Target Endpoint
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 text-xs">
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px]">Server Endpoint</span>
                        <span className="font-mono text-white font-semibold">{cd.v2boxContainer.outboundServer}:{cd.v2boxContainer.outboundPort}</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px]">SNI / ServerName</span>
                        <span className="font-mono text-cyan-300 break-all">{cd.v2boxContainer.sni || 'None'}</span>
                      </div>
                      <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                        <span className="text-slate-400 block text-[10px]">UUID / Secret Key</span>
                        <span className="font-mono text-slate-300 break-all">{cd.v2boxContainer.uuid || 'Configured via Profile'}</span>
                      </div>
                      {cd.v2boxContainer.path && (
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-400 block text-[10px]">Path / gRPC Service</span>
                          <span className="font-mono text-cyan-300">{cd.v2boxContainer.path}</span>
                        </div>
                      )}
                      {cd.v2boxContainer.realityPublicKey && (
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-400 block text-[10px]">Reality Public Key (pbk)</span>
                          <span className="font-mono text-amber-300 break-all">{cd.v2boxContainer.realityPublicKey}</span>
                        </div>
                      )}
                      {cd.v2boxContainer.realityShortId && (
                        <div className="p-2.5 rounded bg-slate-900 border border-slate-800">
                          <span className="text-slate-400 block text-[10px]">Reality Short ID (sid)</span>
                          <span className="font-mono text-amber-300">{cd.v2boxContainer.realityShortId}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Supported Protocols Matrix */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                    <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                      V2Box Supported Protocols Engine Matrix
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-3 gap-1.5 text-xs">
                      {cd.v2boxContainer.supportedProtocols.map((proto, pIdx) => (
                        <div key={pIdx} className="p-2 rounded bg-slate-900 border border-slate-800/80 flex items-center gap-2">
                          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 shrink-0"></span>
                          <span className="font-mono text-slate-200 text-[11px] truncate">{proto}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Raw Envelope / Hex Preview */}
                  {cd.v2boxContainer.rawEnvelopeHexPreview && (
                    <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                          V2Box Raw Encrypted Envelope Header Hex Preview
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText('v2boxHex', cd.v2boxContainer!.rawEnvelopeHexPreview!)}
                          className="text-xs text-cyan-400 hover:underline cursor-pointer"
                        >
                          {copiedKey === 'v2boxHex' ? 'Copied Hex!' : 'Copy Hex'}
                        </button>
                      </div>
                      <div className="font-mono text-xs text-cyan-300/80 break-all bg-slate-900 p-2.5 rounded-lg border border-slate-800">
                        {cd.v2boxContainer.rawEnvelopeHexPreview}
                      </div>
                    </div>
                  )}

                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      disabled={loading}
                      onClick={() => handleInspect()}
                      className="px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-bold text-xs cursor-pointer hover:opacity-90 transition shadow-md shadow-cyan-500/20"
                    >
                      Run Live Verification Probe for {cd.v2boxContainer.profileName}
                    </button>
                  </div>
                </div>
              )}

              {/* ==================== SSH CUSTOM (Ssc://) DECRYPTED PROFILE INSPECTOR CARD ==================== */}
              {showSscCard && cd.sscContainer && (
                <div className="bg-slate-900/75 border border-amber-500/40 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2.5">
                    <div className="flex items-center gap-2.5 flex-wrap min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        SSH Custom (<code className="text-amber-300 break-all">{cd.sscContainer.scheme}</code>) 3-Layer Decrypted Profile
                      </h3>
                    </div>
                    <div className="flex items-center gap-1.5 sm:gap-2 flex-wrap">
                      {cd.sscContainer.generatedSscUri && (
                        <button
                          type="button"
                          onClick={() => copyText('sscCloudUri', cd.sscContainer!.generatedSscUri!)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 cursor-pointer"
                        >
                          {copiedKey === 'sscCloudUri' ? 'Copied Ssc:// Link!' : 'Copy Ssc:// Cloud Link'}
                        </button>
                      )}
                      {cd.sscContainer.rawSscFileHex && (
                        <button
                          type="button"
                          onClick={() => copyText('sscRawFileHex', cd.sscContainer!.rawSscFileHex!)}
                          className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 cursor-pointer"
                        >
                          {copiedKey === 'sscRawFileHex' ? 'Copied .ssc Hex!' : 'Copy .ssc File Hex'}
                        </button>
                      )}
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 whitespace-nowrap">
                        DECRYPTED ({cd.sscContainer.profileCount} Profile{cd.sscContainer.profileCount !== 1 ? 's' : ''} • v{cd.sscContainer.outerVersion})
                      </span>
                    </div>
                  </div>

                  {/* Outer Container Metadata */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                    {[
                      { label: 'Author / Title (f)', value: cd.sscContainer.outerAuthorTitle || 'N/A' },
                      { label: 'Banner Note (b)', value: cd.sscContainer.outerBannerNote || 'N/A' },
                      { label: 'Expiry Date (c)', value: cd.sscContainer.outerExpiryDate || 'No Expiry' },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-amber-300/90">
                            {item.label}
                          </div>
                          <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                            {item.value}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => copyText(item.label, item.value)}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                        >
                          {copiedKey === item.label ? 'Copied!' : 'Copy'}
                        </button>
                      </div>
                    ))}
                  </div>

                  {/* Decrypted Profile(s) */}
                  {cd.sscContainer.profiles?.map((prof, pIdx) => (
                    <div
                      key={pIdx}
                      className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-3"
                    >
                      <div className="flex items-center justify-between border-b border-slate-800 pb-2 flex-wrap gap-2">
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 text-xs font-bold font-mono">
                            #{pIdx + 1} (ID: {prof.PROFILE_ID})
                          </span>
                          <span className="text-sm font-bold text-white">{prof.CONFIG_NAME}</span>
                        </div>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-500/15 text-cyan-300">
                            Tunnel: {prof.TUNNEL_TYPE} (r={prof.PROTOCOL_ID})
                          </span>
                          {prof.IS_PREMIUM && (
                            <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-500/15 text-emerald-300">
                              PREMIUM
                            </span>
                          )}
                        </div>
                      </div>

                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {[
                          { label: 'SlowDNS Nameserver (w / NS_SERVER)', value: prof.NS_SERVER || '(None)' },
                          { label: 'DNS Resolver IP (v / DNS)', value: prof.DNS_RESOLVER || '(None)' },
                          { label: 'Server Host / SNI (l / SNI_OR_HOST)', value: prof.SNI_OR_HOST || '(None)' },
                          {
                            label: 'Ports (m=PORT / z=SSH_PORT / q=UDPGW)',
                            value: `Port: ${prof.PORT} | SSH: ${prof.SSH_PORT} | UDPGW: ${prof.UDPGW_PORT}`,
                          },
                          { label: 'SSH Username (o / USERNAME)', value: prof.USERNAME || '(None)' },
                          {
                            label: 'SSH Password (p / PASSWORD)',
                            value: showPassword
                              ? prof.PASSWORD || '(None)'
                              : prof.PASSWORD
                                ? `${'•'.repeat(Math.min(prof.PASSWORD.length, 10))} (${prof.PASSWORD.length} chars — click Show)`
                                : '(None)',
                            rawCopy: prof.PASSWORD || '',
                            isPassword: true,
                          },
                          ...(prof.PAYLOAD
                            ? [{ label: 'HTTP Payload (g / PAYLOAD)', value: prof.PAYLOAD }]
                            : []),
                          ...(prof.PROXY
                            ? [{ label: 'HTTP Proxy (h:i)', value: `${prof.PROXY}:${prof.PROXY_PORT}` }]
                            : []),
                        ].map((field: any) => (
                          <div
                            key={field.label}
                            className="p-2.5 rounded-lg bg-slate-900/90 border border-slate-800 flex items-center justify-between gap-2"
                          >
                            <div className="min-w-0">
                              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                                {field.label}
                              </div>
                              <div className="text-xs font-mono text-slate-100 truncate mt-0.5">
                                {field.value}
                              </div>
                            </div>
                            <div className="flex items-center gap-1 shrink-0">
                              {field.isPassword && (
                                <button
                                  type="button"
                                  onClick={() => setShowPassword(!showPassword)}
                                  className="px-2 py-1 rounded bg-amber-500/20 hover:bg-amber-500/30 text-[11px] text-amber-300 cursor-pointer"
                                >
                                  {showPassword ? 'Hide' : 'Show'}
                                </button>
                              )}
                              <button
                                type="button"
                                onClick={() => copyText(`${pIdx}-${field.label}`, field.rawCopy ?? field.value)}
                                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-[11px] text-slate-300 cursor-pointer"
                              >
                                {copiedKey === `${pIdx}-${field.label}` ? 'Copied!' : 'Copy'}
                              </button>
                            </div>
                          </div>
                        ))}
                      </div>

                      {(prof.PUBKEY || prof.PUBKEY_RAW_HEX) && (
                        <div className={`p-3 rounded-lg space-y-1 ${prof.PUBKEY_DECRYPTED_SUCCESSFULLY ? 'bg-slate-900/95 border border-purple-500/30' : 'bg-amber-950/40 border border-amber-700/50'}`}>
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-[11px] font-semibold uppercase tracking-wider text-purple-300">
                              SlowDNS (DNSTT) Server Public Key (x / PUBKEY)
                              {prof.PUBKEY_DECRYPTED_SUCCESSFULLY ? (
                                <span className="ml-2 text-emerald-400 text-[9px] font-normal">
                                  {prof.PUBKEY.length === 64 ? '✓ Curve25519 Verified (64 chars)' : `✓ Decrypted (${prof.PUBKEY.length} chars)`}
                                </span>
                              ) : prof.PUBKEY_RAW_HEX ? (
                                <span className="ml-2 text-amber-300 text-[9px] font-normal">⚠ Encrypted Data</span>
                              ) : null}
                            </span>
                            <button
                              type="button"
                              onClick={() => copyText(`${pIdx}-pubkey`, prof.PUBKEY || prof.PUBKEY_RAW_HEX)}
                              className="text-xs text-cyan-400 hover:underline cursor-pointer whitespace-nowrap"
                            >
                              {copiedKey === `${pIdx}-pubkey` ? 'Copied!' : 'Copy Key'}
                            </button>
                          </div>
                          <p className="text-xs font-mono text-emerald-300 break-all">
                            {prof.PUBKEY || (
                              <span className="text-amber-400">
                                {prof.PUBKEY_RAW_HEX?.slice(0, 80)}
                                {prof.PUBKEY_RAW_HEX?.length > 80 ? '...' : ''}
                              </span>
                            )}
                          </p>
                          {!prof.PUBKEY_DECRYPTED_SUCCESSFULLY && prof.PUBKEY_RAW_HEX && (
                            <div className="mt-2 p-2 bg-amber-950/50 rounded border border-amber-700/30">
                              <p className="text-[10px] text-amber-300 font-mono">
                                ⚠️ Decryption Status: Raw encrypted hex shown for verification
                              </p>
                              <p className="text-[9px] text-amber-400 mt-1">
                                Length: {prof.PUBKEY_RAW_HEX.length} hex chars ({Math.floor(prof.PUBKEY_RAW_HEX.length / 2)} bytes)
                              </p>
                            </div>
                          )}
                        </div>
                      )}

                      <div className="flex items-center justify-between flex-wrap gap-2 pt-1 text-[11px] text-slate-400">
                        <span className="font-mono">
                          Layer 3 Nonce Seed (b): <strong className="text-slate-300">{prof.USER_KEY_NONCE_SEED}</strong>
                        </span>
                        <div className="flex items-center gap-1.5 flex-wrap">
                          {[
                            { k: 'HWID Lock', v: prof.HWID_LOCK },
                            { k: 'Root Lock', v: prof.ROOT_LOCK },
                            { k: 'PlayStore Lock', v: prof.PLAYSTORE_LOCK },
                            { k: 'Expiry Lock', v: prof.EXPIRY_LOCK },
                            { k: 'Password Lock', v: prof.PASSWORD_LOCK },
                          ].map((lk) => (
                            <span
                              key={lk.k}
                              className={`px-2 py-0.5 rounded font-semibold ${lk.v ? 'bg-rose-500/20 text-rose-300' : 'bg-slate-800 text-slate-400'
                                }`}
                            >
                              {lk.k}: {lk.v ? 'ON' : 'OFF'}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* ==================== V2RAY / XRAY CORE INSPECTOR CARD ==================== */}
              {showV2RayCard && (
                <div className="bg-slate-900/75 border border-emerald-500/30 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        V2Ray / Xray Core Configuration ({cd.v2ray.protocol.toUpperCase()})
                      </h3>
                    </div>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 whitespace-nowrap">
                        {cd.v2ray.network.toUpperCase()} + {cd.v2ray.security.toUpperCase()}
                      </span>
                      {cd.v2ray.activeInMode && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 whitespace-nowrap">
                          ACTIVE MODE
                        </span>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {[
                      { label: 'V2Ray Protocol', value: cd.v2ray.protocol.toUpperCase() },
                      {
                        label: 'V2Ray Server Host : Port',
                        value: cd.v2ray.serverHost ? `${cd.v2ray.serverHost}:${cd.v2ray.serverPort}` : '',
                      },
                      { label: 'Transport Network', value: cd.v2ray.network.toUpperCase() },
                      { label: 'Stream Security', value: cd.v2ray.security.toUpperCase() },
                      { label: 'TLS / REALITY SNI (ServerName)', value: cd.v2ray.sni },
                      { label: 'WebSocket Host / Authority', value: cd.v2ray.wsHost },
                      { label: 'WebSocket Path / gRPC Service', value: cd.v2ray.wsPath },
                      { label: 'VMess AlterId', value: cd.v2ray.alterId },
                      { label: 'REALITY Public Key (pbk)', value: cd.v2ray.publicKey },
                      { label: 'REALITY Short ID (sid)', value: cd.v2ray.shortId },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                            {item.label}
                          </div>
                          <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                            {item.value || <span className="text-slate-600 italic">(empty)</span>}
                          </div>
                        </div>
                        {item.value && (
                          <button
                            type="button"
                            onClick={() => copyText(item.label, item.value)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                          >
                            {copiedKey === item.label ? 'Copied!' : 'Copy'}
                          </button>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* V2Ray UUID Box */}
                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                        V2Ray Client UUID / Trojan Password
                      </span>
                      {cd.v2ray.uuid && (
                        <button
                          type="button"
                          onClick={() => copyText('v2rayUuid', cd.v2ray.uuid)}
                          className="text-xs text-cyan-400 hover:underline cursor-pointer"
                        >
                          {copiedKey === 'v2rayUuid' ? 'Copied!' : 'Copy UUID'}
                        </button>
                      )}
                    </div>
                    <div className="text-xs font-mono break-all mt-1">
                      {cd.v2ray.uuid && !cd.v2ray.uuid.includes('🔒') ? (
                        <span className="text-emerald-300">{cd.v2ray.uuid}</span>
                      ) : (
                        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/25">
                          <span className="text-amber-300 font-bold flex items-center gap-1.5">
                            🔒 Protected Profile (Lock All) — Injected into Xray Outbound Core (libaio.so)
                          </span>
                          <span className="text-[11px] text-slate-400">
                            Dispatched directly by dev/epro/xray Controller at connection time
                          </span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* V2Ray Engine Flags */}
                  <div className="flex flex-wrap gap-2">
                    <span className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300">
                      Domain Strategy: <strong className="text-cyan-300 font-mono">{cd.v2ray.domainStrategy}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300">
                      FakeDNS: <strong className="text-emerald-300">{cd.v2ray.fakeDns ? 'Enabled' : 'Disabled'}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300">
                      Performance Mode: <strong className="text-emerald-300">{cd.v2ray.performanceMode ? 'On' : 'Off'}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300">
                      Smart Routing: <strong className="text-cyan-300">{cd.v2ray.smartRouting ? 'On' : 'Off'}</strong>
                    </span>
                    <span className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300">
                      Allow Insecure TLS: <strong className="text-amber-300">{cd.v2ray.allowInsecure ? 'Yes' : 'No'}</strong>
                    </span>
                  </div>

                  {/* Generated Share URI (vless:// / vmess:// / trojan://) & Xray Outbound JSON */}
                  {/* Generated Share URI or Locked Outbound Notice */}
                  {cd.v2ray.generatedShareUri ? (
                    <div className="p-3.5 rounded-xl bg-emerald-950/25 border border-emerald-500/30 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold uppercase tracking-wider text-emerald-300">
                          Generated Standard Share URI (Compatible with v2rayNG / NekoBox / Xray)
                        </span>
                        <div className="flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => setShowXrayJson(!showXrayJson)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 cursor-pointer"
                          >
                            {showXrayJson ? 'Hide Xray JSON' : 'View Xray Outbound JSON'}
                          </button>
                          <button
                            type="button"
                            onClick={() => copyText('shareUri', cd.v2ray.generatedShareUri!)}
                            className="px-2.5 py-1 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-xs font-semibold text-emerald-300 border border-emerald-500/30 cursor-pointer"
                          >
                            {copiedKey === 'shareUri' ? 'Copied URI!' : 'Copy Share Link'}
                          </button>
                        </div>
                      </div>
                      <p className="text-xs font-mono text-slate-200 break-all bg-slate-950/90 p-2.5 rounded-lg border border-slate-800">
                        {cd.v2ray.generatedShareUri}
                      </p>

                      {showXrayJson && cd.v2ray.generatedXrayOutbound && (
                        <div className="pt-2">
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                              Generated Xray Core Outbound Object
                            </span>
                            <button
                              type="button"
                              onClick={() =>
                                copyText('xrayJson', JSON.stringify(cd.v2ray.generatedXrayOutbound, null, 2))
                              }
                              className="text-xs text-cyan-400 hover:underline cursor-pointer"
                            >
                              {copiedKey === 'xrayJson' ? 'Copied JSON!' : 'Copy JSON'}
                            </button>
                          </div>
                          <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-200 overflow-x-auto max-h-64">
                            {JSON.stringify(cd.v2ray.generatedXrayOutbound, null, 2)}
                          </pre>
                        </div>
                      )}
                    </div>
                  ) : (cd.v2ray.uuid?.includes('🔒') || cd.hcContainer?.isLocked) ? (
                    <div className="p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/25 space-y-2">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-semibold uppercase tracking-wider text-amber-300 flex items-center gap-1.5">
                          🔒 Outbound Share Restricted by Author Lock (Lock All)
                        </span>
                        <span className="text-[11px] text-slate-400">
                          App-Encrypted Profile
                        </span>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed font-sans">
                        Plaintext V2Ray URI generation is restricted because the configuration author exported this profile with <strong>Lock All</strong>. The server credentials and UUID are encrypted inside the <code>.hc</code> container and dispatched directly to the embedded Xray engine (<code>libaio.so</code>) at connection time. To share, export the original <code>.hc</code> file or share via the permanent Coldplay cloud link.
                      </p>
                    </div>
                  ) : null}
                </div>
              )}

              {/* ==================== SLOWDNS (DNSTT) INSPECTOR CARD ==================== */}
              {showDnsttCard && (
                <div className="bg-slate-900/75 border border-purple-500/30 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-purple-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">SlowDNS (DNSTT) Configuration</h3>
                    </div>
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-500/15 text-purple-300 border border-purple-500/30 whitespace-nowrap self-start sm:self-auto">
                      Record: {cd.slowDns.recordType}
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {[
                      { label: 'DNSTT Nameserver (NS)', value: cd.slowDns.nameserver },
                      { label: 'DNS Resolver (UDP 53)', value: cd.slowDns.dnsResolver || '8.8.8.8 (Fallback)' },
                      { label: 'DNS Query Record Type', value: cd.slowDns.recordType },
                      { label: 'DNSTT Speed / Window Profile', value: cd.slowDns.windowSize },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                            {item.label}
                          </div>
                          <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                            {item.value || <span className="text-slate-600 italic">(empty)</span>}
                          </div>
                        </div>
                        {item.value && (
                          <button
                            type="button"
                            onClick={() => copyText(item.label, item.value)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                          >
                            {copiedKey === item.label ? 'Copied!' : 'Copy'}
                          </button>
                        )}
                      </div>
                    ))}
                  </div>

                  <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold uppercase tracking-wider text-purple-300">
                        DNSTT Public Key (64-Hex Noise_NK Curve25519)
                      </span>
                      {cd.slowDns.pubkey && (
                        <button
                          type="button"
                          onClick={() => copyText('pubkey', cd.slowDns.pubkey)}
                          className="text-xs text-cyan-400 hover:underline cursor-pointer"
                        >
                          {copiedKey === 'pubkey' ? 'Copied!' : 'Copy Key'}
                        </button>
                      )}
                    </div>
                    <p className="text-xs font-mono text-emerald-300 break-all">
                      {cd.slowDns.pubkey || <span className="text-slate-600 italic">(not configured)</span>}
                    </p>
                  </div>
                </div>
              )}

              {/* ==================== SSH + PROXY + PAYLOAD + SSL INSPECTOR CARD ==================== */}
              {showSshProxyCard && (
                <div className="bg-slate-900/75 border border-cyan-500/30 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shrink-0" />
                      <h3 className="text-base font-bold text-white truncate max-w-full">
                        SSH Credentials, Proxy, SSL (SNI) & HTTP Payload
                      </h3>
                    </div>
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="text-xs text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer self-start sm:self-auto"
                    >
                      {showPassword ? 'Hide Password' : 'Show Password'}
                    </button>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {[
                      { label: 'SSH Server Host', value: cd.ssh.server },
                      { label: 'SSH Port', value: cd.ssh.port },
                      { label: 'SSH Username', value: cd.ssh.username },
                      {
                        label: 'SSH Password',
                        value: showPassword
                          ? cd.ssh.password
                          : cd.ssh.password
                            ? '••••••••••••'
                            : '',
                        rawCopy: cd.ssh.password,
                      },
                      {
                        label: 'Proxy Host : Port',
                        value: cd.proxyAndPayload.proxyHost
                          ? `${cd.proxyAndPayload.proxyHost}:${cd.proxyAndPayload.proxyPort}`
                          : '',
                      },
                      {
                        label: 'SSL / TLS SNI (Bug Host)',
                        value: cd.proxyAndPayload.sni
                          ? `${cd.proxyAndPayload.sni} (SSL Port: ${cd.proxyAndPayload.sslPort})`
                          : '',
                        rawCopy: cd.proxyAndPayload.sni,
                      },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                            {item.label}
                          </div>
                          <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                            {item.value || <span className="text-slate-600 italic">(empty)</span>}
                          </div>
                        </div>
                        {(item.rawCopy || item.value) && (
                          <button
                            type="button"
                            onClick={() => copyText(item.label, item.rawCopy || item.value)}
                            className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 shrink-0 cursor-pointer"
                          >
                            {copiedKey === item.label ? 'Copied!' : 'Copy'}
                          </button>
                        )}
                      </div>
                    ))}
                  </div>

                  {/* HTTP Payload Inspector & Wire Expander */}
                  {cd.proxyAndPayload.payload && (
                    <div className="space-y-3 pt-2">
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                            Raw HTTP Payload Template
                          </span>
                          <button
                            type="button"
                            onClick={() => copyText('payload', cd.proxyAndPayload.payload)}
                            className="text-xs text-cyan-400 hover:underline cursor-pointer"
                          >
                            {copiedKey === 'payload' ? 'Copied!' : 'Copy Payload'}
                          </button>
                        </div>
                        <pre className="text-xs font-mono text-amber-300 whitespace-pre-wrap break-all">
                          {cd.proxyAndPayload.payload}
                        </pre>
                      </div>

                      {cd.proxyAndPayload.payloadExpandedPreview && (
                        <div className="p-3.5 rounded-xl bg-cyan-950/20 border border-cyan-500/30">
                          <div className="flex items-center justify-between mb-1.5 flex-wrap gap-2">
                            <span className="text-xs font-semibold uppercase tracking-wider text-cyan-300">
                              Simulated HTTP Wire Injection Preview
                            </span>
                            <div className="flex items-center gap-1.5 flex-wrap">
                              {cd.proxyAndPayload.payloadDetectedTokens.map((tok) => (
                                <span
                                  key={tok}
                                  className="px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-200 font-mono text-[10px]"
                                >
                                  {tok}
                                </span>
                              ))}
                            </div>
                          </div>
                          <pre className="text-xs font-mono text-slate-200 whitespace-pre-wrap break-all bg-slate-950/90 p-3 rounded-lg border border-slate-800">
                            {cd.proxyAndPayload.payloadExpandedPreview}
                          </pre>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* ==================== HYSTERIA2 INSPECTOR CARD ==================== */}
              {showHysteriaCard && (
                <div className="bg-slate-900/75 border border-amber-500/30 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shrink-0" />
                      <h3 className="text-sm sm:text-base font-bold text-white">Hysteria2 (QUIC / Brutal) Configuration</h3>
                    </div>
                    <span className="self-start sm:self-auto px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-500/15 text-amber-300 border border-amber-500/30">
                      UDP QUIC
                    </span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {[
                      { label: 'Hysteria2 Server : Port', value: cd.hysteria2.server ? `${cd.hysteria2.server}:${cd.hysteria2.port}` : '' },
                      { label: 'Authentication Password', value: cd.hysteria2.auth },
                      { label: 'TLS ServerName (SNI)', value: cd.hysteria2.sni },
                      { label: 'Salamander Obfuscation Key', value: cd.hysteria2.obfs || '(None)' },
                      { label: 'Port Hopping Range (mport)', value: cd.hysteria2.portHoppingRange || '(Single Port)' },
                      { label: 'Bandwidth (Up / Down)', value: `${cd.hysteria2.upMbps} Mbps Up / ${cd.hysteria2.downMbps} Mbps Down` },
                    ].map((item) => (
                      <div
                        key={item.label}
                        className="p-3 rounded-xl bg-slate-950/70 border border-slate-800/90 flex items-center justify-between gap-2"
                      >
                        <div className="min-w-0">
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                            {item.label}
                          </div>
                          <div className="text-sm font-mono text-slate-100 truncate mt-0.5">
                            {item.value || <span className="text-slate-600 italic">(empty)</span>}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {cd.hysteria2.generatedHy2Uri && (
                    <div className="p-3.5 rounded-xl bg-amber-950/20 border border-amber-500/30">
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-semibold uppercase tracking-wider text-amber-300">
                          Generated Hysteria2 URI (hy2://)
                        </span>
                        <button
                          type="button"
                          onClick={() => copyText('hy2Uri', cd.hysteria2.generatedHy2Uri!)}
                          className="text-xs text-amber-300 hover:underline cursor-pointer"
                        >
                          {copiedKey === 'hy2Uri' ? 'Copied!' : 'Copy hy2:// URI'}
                        </button>
                      </div>
                      <p className="text-xs font-mono text-slate-200 break-all">{cd.hysteria2.generatedHy2Uri}</p>
                    </div>
                  )}
                </div>
              )}

              {/* ==================== WIREGUARD & SLIPSTREAM INSPECTOR CARD ==================== */}
              {showWireGuardCard && (
                <div className="bg-slate-900/75 border border-rose-500/30 rounded-2xl p-4 sm:p-5 space-y-4">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                    <div className="flex items-center gap-2.5">
                      <span className="w-2.5 h-2.5 rounded-full bg-rose-400 shrink-0" />
                      <h3 className="text-sm sm:text-base font-bold text-white">WireGuard & Slipstream Configuration</h3>
                    </div>
                  </div>

                  {cd.wireguard.parsed ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800">
                        <div className="text-[11px] font-semibold uppercase text-slate-400">[Interface] Tunnel Address</div>
                        <div className="text-sm font-mono text-slate-100 mt-0.5">{cd.wireguard.parsed.interface.address || '(missing)'}</div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800">
                        <div className="text-[11px] font-semibold uppercase text-slate-400">[Interface] Private Key</div>
                        <div className="text-sm font-mono text-emerald-300 mt-0.5">
                          {cd.wireguard.parsed.interface.privateKeyMasked}{' '}
                          ({cd.wireguard.parsed.interface.validPrivateKey ? 'Valid Base64' : 'Invalid'})
                        </div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800">
                        <div className="text-[11px] font-semibold uppercase text-slate-400">[Peer] Endpoint</div>
                        <div className="text-sm font-mono text-cyan-300 mt-0.5">{cd.wireguard.parsed.peer.endpoint || '(missing)'}</div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800">
                        <div className="text-[11px] font-semibold uppercase text-slate-400">[Peer] Public Key</div>
                        <div className="text-sm font-mono text-slate-100 truncate mt-0.5">{cd.wireguard.parsed.peer.publicKey || '(missing)'}</div>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 italic">No WireGuard INI profile stored in this config.</p>
                  )}

                  {cd.slipstream.present && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2 border-t border-slate-800">
                      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800">
                        <div className="text-[11px] font-semibold uppercase text-slate-400">Slipstream Domain</div>
                        <div className="text-sm font-mono text-slate-100 mt-0.5">{cd.slipstream.domain}</div>
                      </div>
                      <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800">
                        <div className="text-[11px] font-semibold uppercase text-slate-400">Slipstream Segments & Direct</div>
                        <div className="text-sm font-mono text-slate-100 mt-0.5">
                          Segments: {cd.slipstream.segments} | Direct: {String(cd.slipstream.direct)}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ==================== FIELD-BY-FIELD VALIDATION CHECKLIST ==================== */}
              <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4 sm:p-5">
                <h3 className="text-base font-bold text-white border-b border-slate-800 pb-3 mb-4">
                  Configuration Verification Checklist ({result.validationChecks?.length || 0} Checks)
                </h3>
                <div className="space-y-3">
                  {result.validationChecks?.map((chk) => (
                    <div
                      key={chk.id}
                      className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800/90 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    >
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          {renderStatusBadge(chk.status)}
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-300">
                            {chk.protocol}
                          </span>
                          <span className="text-sm font-semibold text-slate-200">{chk.label}</span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">{chk.detail}</p>
                      </div>
                      <div className="text-xs font-mono text-cyan-300 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800 shrink-0 max-w-full sm:max-w-xs truncate">
                        {chk.value}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Right Column: Live Protocol Handshakes & Server Reachability (5 cols) */}
            <div className="lg:col-span-5 space-y-6">
              <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4 sm:p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-slate-800 pb-3 gap-2">
                  <h3 className="text-base font-bold text-white">Live Protocol Handshakes & Probes</h3>
                  <span className="self-start sm:self-auto text-xs px-2.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/30">
                    Real-Time Verification
                  </span>
                </div>

                {!diag ? (
                  <p className="text-sm text-slate-400">Live network probes were disabled for this request.</p>
                ) : (
                  <div className="space-y-4">
                    {/* 1. Live TLS / SNI Certificate Handshake Inspector */}
                    {diag.tlsHandshakeProbe && (
                      <div className="p-4 rounded-xl bg-slate-950/90 border border-indigo-500/30 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-indigo-300">
                            TLS / SNI Certificate Handshake
                          </span>
                          {renderStatusBadge(diag.tlsHandshakeProbe.success ? 'pass' : 'fail')}
                        </div>
                        <div className="text-xs space-y-1 text-slate-300">
                          <div>
                            SNI Spoofed:{' '}
                            <span className="font-mono text-cyan-300">{diag.tlsHandshakeProbe.sniSent}</span>
                          </div>
                          {diag.tlsHandshakeProbe.success ? (
                            <>
                              <div>
                                Protocol & Cipher:{' '}
                                <span className="font-mono text-emerald-300">
                                  {diag.tlsHandshakeProbe.protocol} • {diag.tlsHandshakeProbe.cipher}
                                </span>
                              </div>
                              <div>
                                ALPN Negotiated:{' '}
                                <span className="font-mono text-amber-300">
                                  {diag.tlsHandshakeProbe.alpnProtocol || 'none'}
                                </span>{' '}
                                ({diag.tlsHandshakeProbe.latencyMs}ms)
                              </div>
                              <div>
                                Cert Subject / Issuer:{' '}
                                <span className="font-mono text-slate-200">
                                  {diag.tlsHandshakeProbe.certSubject || 'Unknown'} ({diag.tlsHandshakeProbe.certIssuer || 'Unknown'})
                                </span>
                              </div>
                              {diag.tlsHandshakeProbe.certDaysRemaining !== null && (
                                <div>
                                  Cert Validity:{' '}
                                  <span
                                    className={`font-mono ${diag.tlsHandshakeProbe.certDaysRemaining > 0 ? 'text-emerald-400' : 'text-rose-400'
                                      }`}
                                  >
                                    {diag.tlsHandshakeProbe.certDaysRemaining} days remaining (until{' '}
                                    {diag.tlsHandshakeProbe.certValidTo})
                                  </span>
                                </div>
                              )}
                            </>
                          ) : (
                            <div className="text-rose-400 font-medium">{diag.tlsHandshakeProbe.error}</div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* 2. Live V2Ray WebSocket (WS) Upgrade Probe */}
                    {diag.v2rayWsUpgradeProbe && (
                      <div className="p-4 rounded-xl bg-slate-950/90 border border-emerald-500/30 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-emerald-300">
                            V2Ray WebSocket (CDN) HTTP Upgrade Probe
                          </span>
                          {renderStatusBadge(
                            diag.v2rayWsUpgradeProbe.statusCode === 101
                              ? 'pass'
                              : diag.v2rayWsUpgradeProbe.responded
                                ? 'warn'
                                : 'fail'
                          )}
                        </div>
                        {diag.v2rayWsUpgradeProbe.responded ? (
                          <div className="text-xs space-y-1.5 text-slate-300">
                            <div>
                              HTTP Status:{' '}
                              <span
                                className={`font-mono font-bold ${diag.v2rayWsUpgradeProbe.statusCode === 101
                                  ? 'text-emerald-400'
                                  : 'text-amber-300'
                                  }`}
                              >
                                {diag.v2rayWsUpgradeProbe.statusLine}
                              </span>{' '}
                              ({diag.v2rayWsUpgradeProbe.latencyMs}ms)
                            </div>
                            {diag.v2rayWsUpgradeProbe.serverHeader && (
                              <div>
                                Edge Server:{' '}
                                <span className="font-mono text-cyan-300">
                                  {diag.v2rayWsUpgradeProbe.serverHeader}
                                  {diag.v2rayWsUpgradeProbe.cfRay ? ` (CF-RAY: ${diag.v2rayWsUpgradeProbe.cfRay})` : ''}
                                </span>
                              </div>
                            )}
                            {diag.v2rayWsUpgradeProbe.rawHeadersPreview && (
                              <pre className="p-2 rounded bg-slate-900 text-[11px] font-mono text-slate-300 overflow-x-auto">
                                {diag.v2rayWsUpgradeProbe.rawHeadersPreview}
                              </pre>
                            )}
                          </div>
                        ) : (
                          <div className="text-xs text-rose-400">{diag.v2rayWsUpgradeProbe.error}</div>
                        )}
                      </div>
                    )}

                    {/* 3. Live HTTP Payload Injection Probe */}
                    {diag.httpPayloadProbe && (
                      <div className="p-4 rounded-xl bg-slate-950/90 border border-cyan-500/30 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                            Live HTTP Payload Injection Response
                          </span>
                          {renderStatusBadge(diag.httpPayloadProbe.responded ? 'pass' : 'fail')}
                        </div>
                        {diag.httpPayloadProbe.responded ? (
                          <div className="text-xs space-y-1.5 text-slate-300">
                            <div>
                              Server Response:{' '}
                              <span className="font-mono font-bold text-emerald-400">
                                {diag.httpPayloadProbe.statusLine}
                              </span>{' '}
                              ({diag.httpPayloadProbe.latencyMs}ms)
                            </div>
                            {diag.httpPayloadProbe.rawHeadersPreview && (
                              <pre className="p-2 rounded bg-slate-900 text-[11px] font-mono text-slate-300 overflow-x-auto">
                                {diag.httpPayloadProbe.rawHeadersPreview}
                              </pre>
                            )}
                          </div>
                        ) : (
                          <div className="text-xs text-rose-400">{diag.httpPayloadProbe.error}</div>
                        )}
                      </div>
                    )}

                    {/* 4. V2Ray TCP Port Probe */}
                    {diag.v2rayTcpProbe && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                            V2Ray Server TCP Reachability ({cd.v2ray.serverHost}:{cd.v2ray.serverPort})
                          </span>
                          {renderStatusBadge(diag.v2rayTcpProbe.reachable ? 'pass' : 'fail')}
                        </div>
                        <div className="text-xs text-slate-300">
                          {diag.v2rayTcpProbe.reachable ? (
                            <span className="text-emerald-400 font-semibold">
                              Connected in {diag.v2rayTcpProbe.latencyMs}ms
                            </span>
                          ) : (
                            <span className="text-rose-400">{diag.v2rayTcpProbe.error}</span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* 5. DNSTT Nameserver & UDP 53 Probe */}
                    {diag.nameserverDns && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                            DNSTT Nameserver DNS Lookup
                          </span>
                          {renderStatusBadge(
                            diag.nameserverDns.ipv4?.length > 0 || diag.nameserverDns.ns?.length > 0 ? 'pass' : 'fail'
                          )}
                        </div>
                        <div className="text-xs font-mono text-cyan-300 break-all">{diag.nameserverDns.domain}</div>
                        <div className="text-xs text-slate-300 space-y-1">
                          <div>
                            A Records (IPv4):{' '}
                            <span className="font-mono text-slate-100">
                              {diag.nameserverDns.ipv4?.length ? diag.nameserverDns.ipv4.join(', ') : 'None'}
                            </span>
                          </div>
                          <div>
                            NS Records:{' '}
                            <span className="font-mono text-slate-100">
                              {diag.nameserverDns.ns?.length ? diag.nameserverDns.ns.join(', ') : 'None'}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {diag.dnsUdpProbe && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                            UDP Port 53 DNSTT Query Probe
                          </span>
                          {renderStatusBadge(
                            diag.dnsUdpProbe.reachable && diag.dnsUdpProbe.rcode === 0
                              ? 'pass'
                              : diag.dnsUdpProbe.reachable
                                ? 'warn'
                                : 'fail'
                          )}
                        </div>
                        <div className="text-xs text-slate-300">
                          {diag.dnsUdpProbe.reachable ? (
                            <>
                              <div>
                                Response Time:{' '}
                                <span className="font-mono text-emerald-400">{diag.dnsUdpProbe.latencyMs}ms</span> • DNS RCODE:{' '}
                                <span className="font-mono text-amber-300">
                                  {diag.dnsUdpProbe.rcode} (
                                  {diag.dnsUdpProbe.rcode === 0
                                    ? 'NOERROR - DNSTT Server Active'
                                    : diag.dnsUdpProbe.rcode === 2
                                      ? 'SERVFAIL - Remote dnstt-server Down/Blocked'
                                      : diag.dnsUdpProbe.rcode === 3
                                        ? 'NXDOMAIN - Domain Does Not Exist'
                                        : 'Other'}
                                  )
                                </span>
                              </div>
                            </>
                          ) : (
                            <span className="text-rose-400">{diag.dnsUdpProbe.error}</span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* 6. SSH TCP Probe */}
                    {diag.sshTcpProbe && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                            SSH TCP Probe ({cd.ssh.server}:{cd.ssh.port})
                          </span>
                          {renderStatusBadge(diag.sshTcpProbe.reachable ? 'pass' : 'fail')}
                        </div>
                        <div className="text-xs text-slate-300">
                          {diag.sshTcpProbe.reachable ? (
                            <>
                              <div className="text-emerald-400 font-semibold">
                                Reachable ({diag.sshTcpProbe.latencyMs}ms)
                              </div>
                              {diag.sshTcpProbe.banner && (
                                <div className="font-mono text-[11px] text-slate-300 bg-slate-900 p-2 rounded mt-1">
                                  Banner: {diag.sshTcpProbe.banner}
                                </div>
                              )}
                            </>
                          ) : (
                            <span className="text-rose-400">{diag.sshTcpProbe.error}</span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* 7. Hysteria2 / Proxy / WireGuard Endpoint DNS & TCP Probes */}
                    {diag.proxyTcpProbe && (
                      <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 space-y-1.5">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
                            Proxy TCP Probe ({cd.proxyAndPayload.proxyHost}:{cd.proxyAndPayload.proxyPort})
                          </span>
                          {renderStatusBadge(diag.proxyTcpProbe.reachable ? 'pass' : 'fail')}
                        </div>
                        <div className="text-xs text-slate-300">
                          {diag.proxyTcpProbe.reachable ? (
                            <span className="text-emerald-400 font-semibold">
                              Reachable ({diag.proxyTcpProbe.latencyMs}ms)
                            </span>
                          ) : (
                            <span className="text-rose-400">{diag.proxyTcpProbe.error}</span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Raw Decrypted JSON Toggle */}
              <div className="bg-slate-900/75 border border-slate-800 rounded-2xl p-4 sm:p-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-bold text-white">Full Decrypted Payload (JSON)</h3>
                    <p className="text-xs text-slate-400">
                      Complete raw configuration object extracted from the encrypted container
                    </p>
                  </div>
                  <div className="flex items-center gap-2 self-start sm:self-auto">
                    <button
                      type="button"
                      onClick={() =>
                        copyText('rawJson', JSON.stringify(result.rawDecryptedConfig, null, 2))
                      }
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-cyan-300 cursor-pointer active:scale-95"
                    >
                      {copiedKey === 'rawJson' ? 'Copied JSON!' : 'Copy JSON'}
                    </button>
                    <button
                      type="button"
                      onClick={() => setShowRawJson(!showRawJson)}
                      className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 cursor-pointer active:scale-95"
                    >
                      {showRawJson ? 'Hide' : 'Show'}
                    </button>
                  </div>
                </div>

                {showRawJson && (
                  <pre className="mt-4 p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-emerald-300 overflow-x-auto max-h-96">
                    {JSON.stringify(result.rawDecryptedConfig, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
