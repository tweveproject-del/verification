'use client';

import React, { useState, useEffect } from 'react';
import {
  TANZANIA_CARRIERS,
  ALL_ACTIVE_VPN_FILES,
  TanzaniaCarrier,
  TanzaniaHostLine,
  TanzaniaVerifiedTemplate
} from '../tanzania-carriers';

interface HostHealthState {
  status: 'idle' | 'probing' | 'active' | 'offline';
  latencyMs?: number;
  ips?: string[];
  testedAt?: string;
}

interface CustomHostLine extends TanzaniaHostLine {
  id: string;
  carrierId: string;
  isCustom: boolean;
  addedAt: string;
}

interface CustomTemplate extends TanzaniaVerifiedTemplate {
  isCustom: boolean;
  addedAt: string;
}

interface TanzaniaCarrierHubProps {
  onLoadConfig: (configContent: string) => void;
  onRunInspect?: () => void;
}

export default function TanzaniaCarrierHub({ onLoadConfig, onRunInspect }: TanzaniaCarrierHubProps) {
  const [activeTab, setActiveTab] = useState<'carrier' | 'all_files' | 'add_new'>('carrier');
  const [selectedCarrierId, setSelectedCarrierId] = useState<string>('vodacom');
  const [formatFilter, setFormatFilter] = useState<string>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(true);

  // Auto-Sync and Live DoH Probe State
  const [autoSyncEnabled, setAutoSyncEnabled] = useState<boolean>(false);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [lastSyncedTime, setLastSyncedTime] = useState<string | null>(null);
  const [secondsUntilNextSync, setSecondsUntilNextSync] = useState<number>(45);
  const [hostHealth, setHostHealth] = useState<Record<string, HostHealthState>>({});

  // Dynamic / Custom additions stored in state & localStorage
  const [customHosts, setCustomHosts] = useState<CustomHostLine[]>([]);
  const [customFiles, setCustomFiles] = useState<CustomTemplate[]>([]);

  // Add New Form States
  const [addMode, setAddMode] = useState<'host' | 'file_cloud'>('host');
  const [newDomain, setNewDomain] = useState<string>('');
  const [newCarrierId, setNewCarrierId] = useState<string>('vodacom');
  const [newPort, setNewPort] = useState<number>(443);
  const [newTunnelMethod, setNewTunnelMethod] = useState<'TLS / SNI Spoof' | 'CDN WebSocket' | 'Direct HTTP Payload'>('TLS / SNI Spoof');
  const [newCategory, setNewCategory] = useState<'SelfCare & Portal' | 'FinTech & M-Pesa' | 'CDN Front' | 'Gateway'>('SelfCare & Portal');

  const [newFileTitle, setNewFileTitle] = useState<string>('');
  const [newFileFormat, setNewFileFormat] = useState<'.v2box' | '.nm' | '.hat' | '.hc' | '.tnl'>('.v2box');
  const [newFileProtocol, setNewFileProtocol] = useState<string>('VLESS Reality');
  const [newFileHostLine, setNewFileHostLine] = useState<string>('');
  const [newFileRawConfig, setNewFileRawConfig] = useState<string>('');
  const [addSuccessMessage, setAddSuccessMessage] = useState<string | null>(null);

  // Load custom hosts and files from localStorage on client mount
  useEffect(() => {
    try {
      const storedHosts = localStorage.getItem('tweve_tanzania_custom_hosts');
      if (storedHosts) setCustomHosts(JSON.parse(storedHosts));
      const storedFiles = localStorage.getItem('tweve_tanzania_custom_files');
      if (storedFiles) setCustomFiles(JSON.parse(storedFiles));
    } catch {}
  }, []);

  const saveCustomHosts = (hosts: CustomHostLine[]) => {
    setCustomHosts(hosts);
    try {
      localStorage.setItem('tweve_tanzania_custom_hosts', JSON.stringify(hosts));
    } catch {}
  };

  const saveCustomFiles = (files: CustomTemplate[]) => {
    setCustomFiles(files);
    try {
      localStorage.setItem('tweve_tanzania_custom_files', JSON.stringify(files));
    } catch {}
  };

  const activeCarrier: TanzaniaCarrier =
    TANZANIA_CARRIERS.find((c) => c.id === selectedCarrierId) || TANZANIA_CARRIERS[0];

  // Merge built-in host lines with custom added host lines
  const carrierHostLines: (TanzaniaHostLine & { id?: string; isCustom?: boolean })[] = [
    ...activeCarrier.hostLines,
    ...customHosts.filter((h) => h.carrierId === activeCarrier.id),
  ];

  // Merge built-in templates with custom added files
  const carrierTemplates: (TanzaniaVerifiedTemplate & { isCustom?: boolean })[] = [
    ...activeCarrier.templates,
    ...customFiles.filter((f) => f.carrierId === activeCarrier.id),
  ];

  // Consolidated all active files
  const allActiveFilesCombined: (TanzaniaVerifiedTemplate & { isCustom?: boolean })[] = [
    ...ALL_ACTIVE_VPN_FILES,
    ...customFiles,
  ];

  const handleCopy = (text: string, identifier: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(identifier);
      setTimeout(() => setCopiedKey(null), 2000);
    }
  };

  const handleApplyHost = (host: string) => {
    onLoadConfig(host);
    if (onRunInspect) {
      setTimeout(() => onRunInspect(), 150);
    }
  };

  const handleApplyTemplate = (template: TanzaniaVerifiedTemplate) => {
    onLoadConfig(template.rawConfig);
    if (onRunInspect) {
      setTimeout(() => onRunInspect(), 150);
    }
  };

  // Direct File Download for .nm, .v2box, .hat, etc.
  const handleDownloadFile = (template: TanzaniaVerifiedTemplate) => {
    try {
      const blob = new Blob([template.rawConfig], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = template.fileName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      setCopiedKey(`dl-${template.id}`);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (e) {
      console.error('File download failed:', e);
    }
  };

  // Live DoH DNS & Latency Prober
  const probeHost = async (domain: string): Promise<HostHealthState> => {
    const t0 = performance.now();
    try {
      const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, {
        headers: { Accept: 'application/dns-json' },
      });
      const data = await res.json();
      const latencyMs = Math.round(performance.now() - t0);
      const ips = data.Answer ? data.Answer.map((a: any) => a.data).filter(Boolean) : [];
      if (ips.length > 0) {
        return { status: 'active', latencyMs, ips, testedAt: new Date().toLocaleTimeString() };
      } else {
        return { status: 'offline', latencyMs, testedAt: new Date().toLocaleTimeString() };
      }
    } catch {
      return { status: 'offline', latencyMs: 999, testedAt: new Date().toLocaleTimeString() };
    }
  };

  // Batch Auto-Sync All Hosts (Built-in + Custom)
  const runBatchSync = async () => {
    setIsSyncing(true);
    const allDomains = Array.from(
      new Set([
        ...TANZANIA_CARRIERS.flatMap((c) => c.hostLines.map((h) => h.domain)),
        ...customHosts.map((h) => h.domain),
      ])
    );

    const newHealthState: Record<string, HostHealthState> = { ...hostHealth };
    for (const d of allDomains) {
      newHealthState[d] = { status: 'probing' };
    }
    setHostHealth({ ...newHealthState });

    const results = await Promise.all(
      allDomains.map(async (domain) => {
        const state = await probeHost(domain);
        return { domain, state };
      })
    );

    const updated: Record<string, HostHealthState> = {};
    for (const r of results) {
      updated[r.domain] = r.state;
    }
    setHostHealth(updated);
    setIsSyncing(false);
    setLastSyncedTime(new Date().toLocaleTimeString());
    setSecondsUntilNextSync(45);
  };

  // Auto-Sync Periodic Timer
  useEffect(() => {
    if (!autoSyncEnabled) return;
    const interval = setInterval(() => {
      setSecondsUntilNextSync((prev) => {
        if (prev <= 1) {
          runBatchSync();
          return 45;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [autoSyncEnabled, customHosts]);

  // Handler: Add New Host Line and Auto-Inspect
  const handleAddNewHost = async () => {
    const cleanDomain = newDomain.trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    if (!cleanDomain) return;

    const samplePayload = `GET / HTTP/1.1[crlf]Host: ${cleanDomain}[crlf]X-Online-Host: ${cleanDomain}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]`;

    const newHostItem: CustomHostLine = {
      id: `custom-hl-${Date.now()}`,
      domain: cleanDomain,
      carrierId: newCarrierId,
      category: newCategory,
      tunnelMethod: newTunnelMethod,
      protocols: ['NetMod Syna', 'V2Box Reality', 'HA Tunnel', 'HTTP Custom'],
      recommendedPort: newPort,
      samplePayload,
      isCustom: true,
      addedAt: new Date().toLocaleTimeString(),
    };

    const updated = [newHostItem, ...customHosts];
    saveCustomHosts(updated);

    // Auto-probe the newly added domain immediately
    setHostHealth((prev) => ({ ...prev, [cleanDomain]: { status: 'probing' } }));
    probeHost(cleanDomain).then((state) => {
      setHostHealth((prev) => ({ ...prev, [cleanDomain]: state }));
    });

    // Auto-apply to main inspector
    handleApplyHost(cleanDomain);

    setNewDomain('');
    setAddSuccessMessage(`Host line "${cleanDomain}" added and probed live!`);
    setTimeout(() => setAddSuccessMessage(null), 3000);
  };

  // Handler: Add New Config File / Cloud Subscription and Auto-Inspect
  const handleAddNewFile = () => {
    if (!newFileRawConfig.trim()) return;

    const targetCarrier = TANZANIA_CARRIERS.find((c) => c.id === newCarrierId) || TANZANIA_CARRIERS[0];
    const cleanTitle = newFileTitle.trim() || `${targetCarrier.name} Custom ${newFileFormat.toUpperCase()}`;
    const cleanFileName = `${cleanTitle.replace(/\s+/g, '_')}${newFileFormat}`;

    const newTemplateItem: CustomTemplate = {
      id: `custom-tpl-${Date.now()}`,
      title: cleanTitle,
      fileName: cleanFileName,
      carrierId: newCarrierId as any,
      carrierName: targetCarrier.name,
      format: newFileFormat,
      protocol: newFileProtocol,
      hostLineUsed: newFileHostLine.trim() || targetCarrier.hostLines[0].domain,
      description: `Custom added configuration for ${targetCarrier.name}`,
      expiryDate: '2027-01-01',
      isExpired: false,
      rawConfig: newFileRawConfig.trim(),
      isCustom: true,
      addedAt: new Date().toLocaleTimeString(),
    };

    const updated = [newTemplateItem, ...customFiles];
    saveCustomFiles(updated);

    // Immediately trigger live inspection on the newly added file
    handleApplyTemplate(newTemplateItem);

    setNewFileTitle('');
    setNewFileRawConfig('');
    setNewFileHostLine('');
    setAddSuccessMessage(`Configuration "${cleanTitle}" added and inspected live!`);
    setTimeout(() => setAddSuccessMessage(null), 3000);
  };

  const handleRemoveCustomHost = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    saveCustomHosts(customHosts.filter((h) => h.id !== id));
  };

  const handleRemoveCustomFile = (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    saveCustomFiles(customFiles.filter((f) => f.id !== id));
  };

  // Filtered list of all active files
  const filteredActiveFiles = allActiveFilesCombined.filter((f) => {
    if (formatFilter === 'all') return true;
    return f.format === formatFilter;
  });

  return (
    <div className="card-modern rounded-2xl p-4 sm:p-5 shadow-2xl border border-sky-500/30 mb-4 bg-slate-900/90 transition">
      {/* Header with Title and Auto-Sync Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-emerald-500 via-sky-500 to-indigo-600 flex items-center justify-center text-sm shadow-md shadow-sky-500/20 shrink-0">
            🇹🇿
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-sm sm:text-base font-extrabold text-white flex items-center gap-2">
                <span>Tanzania Carrier &amp; Active VPN Files Sync Hub</span>
              </h2>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/70 text-emerald-300 border border-emerald-700/50">
                Live Cloud Sync
              </span>
              {lastSyncedTime && (
                <span className="text-[10px] font-mono text-slate-400 hidden sm:inline">
                  • Synced at {lastSyncedTime}
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-300">
              Synchronize, inspect, and batch-download active host lines, SNI endpoints, and configuration files
            </p>
          </div>
        </div>

        {/* Global Action Bar: Auto-Sync Button, Timer Toggle & Collapse */}
        <div className="flex items-center gap-2 flex-wrap self-end sm:self-auto">
          {/* Manual Run Sync Button */}
          <button
            type="button"
            onClick={runBatchSync}
            disabled={isSyncing}
            className={`px-3 py-1.5 rounded-xl text-xs font-bold border transition flex items-center gap-1.5 cursor-pointer shadow-md ${
              isSyncing
                ? 'bg-sky-950/80 text-sky-400 border-sky-800/80 animate-pulse'
                : 'bg-gradient-to-r from-sky-600 to-indigo-600 hover:opacity-90 text-white border-sky-500/40 shadow-sky-500/20'
            }`}
          >
            <svg
              className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            <span>{isSyncing ? 'Syncing...' : 'Auto-Sync Active Hosts'}</span>
          </button>

          {/* Periodic Auto-Sync Toggle */}
          <button
            type="button"
            onClick={() => {
              const nextState = !autoSyncEnabled;
              setAutoSyncEnabled(nextState);
              if (nextState) runBatchSync();
            }}
            className={`px-2.5 py-1.5 rounded-xl text-xs font-semibold border transition flex items-center gap-1.5 cursor-pointer ${
              autoSyncEnabled
                ? 'bg-emerald-950/70 text-emerald-300 border-emerald-600/60 shadow-sm shadow-emerald-500/20'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border-slate-700'
            }`}
            title="Automatically re-probe all host lines and check active VPN files every 45 seconds"
          >
            <span className={`w-2 h-2 rounded-full ${autoSyncEnabled ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
            <span>{autoSyncEnabled ? `Auto (${secondsUntilNextSync}s)` : 'Auto-Sync Off'}</span>
          </button>

          {/* Hide/Expand Button */}
          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="px-2.5 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 cursor-pointer transition flex items-center gap-1"
          >
            <svg
              className={`w-3.5 h-3.5 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="mt-4 space-y-4">
          {/* Mode Switcher Tabs: Carrier View vs All Active Files Repository vs Add New */}
          <div className="flex items-center gap-2 border-b border-slate-800 pb-2.5 overflow-x-auto no-scrollbar">
            <button
              type="button"
              onClick={() => setActiveTab('carrier')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center gap-2 cursor-pointer ${
                activeTab === 'carrier'
                  ? 'bg-sky-500 text-slate-950 shadow-md shadow-sky-500/20'
                  : 'bg-slate-950/60 hover:bg-slate-800 text-slate-300 border border-slate-800'
              }`}
            >
              <span>🇹🇿 By Carrier Network</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-slate-900/40 font-semibold">
                4 Operators
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('all_files')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center gap-2 cursor-pointer ${
                activeTab === 'all_files'
                  ? 'bg-sky-500 text-slate-950 shadow-md shadow-sky-500/20'
                  : 'bg-slate-950/60 hover:bg-slate-800 text-slate-300 border border-slate-800'
              }`}
            >
              <span>⚡ All Active VPN Files &amp; Clouds</span>
              <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-800/60 font-semibold">
                {allActiveFilesCombined.length} Active
              </span>
            </button>

            <button
              type="button"
              onClick={() => setActiveTab('add_new')}
              className={`px-3.5 py-1.5 rounded-xl text-xs font-bold transition flex items-center gap-1.5 cursor-pointer ${
                activeTab === 'add_new'
                  ? 'bg-indigo-500 text-white shadow-md shadow-indigo-500/20'
                  : 'bg-indigo-950/40 hover:bg-indigo-900/50 text-indigo-300 border border-indigo-800/50'
              }`}
            >
              <span>+ Add &amp; Auto-Inspect</span>
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
            </button>
          </div>

          {/* Alert Message upon Adding */}
          {addSuccessMessage && (
            <div className="bg-emerald-950/50 border border-emerald-700/60 text-emerald-300 px-3 py-2 rounded-xl text-xs flex items-center gap-2 animate-fadeIn">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>{addSuccessMessage}</span>
            </div>
          )}

          {/* TAB 1: CARRIER NETWORK VIEW */}
          {activeTab === 'carrier' && (
            <div className="space-y-4">
              {/* Carrier Selector Tab Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {TANZANIA_CARRIERS.map((carrier) => {
                  const isSelected = carrier.id === selectedCarrierId;
                  return (
                    <button
                      key={carrier.id}
                      type="button"
                      onClick={() => setSelectedCarrierId(carrier.id)}
                      className={`p-2.5 rounded-xl border text-left transition cursor-pointer flex flex-col justify-between ${
                        isSelected
                          ? `${carrier.pillClass} ring-2 ring-sky-400/50 shadow-lg scale-[1.01]`
                          : 'bg-slate-950/50 border-slate-800 hover:border-slate-700 hover:bg-slate-800/40 opacity-75'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-extrabold text-white">{carrier.name}</span>
                        <span
                          className="w-2 h-2 rounded-full"
                          style={{ backgroundColor: carrier.brandColor }}
                        />
                      </div>
                      <span className="text-[10px] text-slate-300 font-mono mt-1">
                        {carrier.badge}
                      </span>
                    </button>
                  );
                })}
              </div>

              {/* Active Carrier Specification Banner */}
              <div className="bg-slate-950/70 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: activeCarrier.brandColor }} />
                  <span className="font-bold text-white text-xs">{activeCarrier.name} Network Specification</span>
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                    MCC-MNC: {activeCarrier.mccMnc}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-[11px] font-mono text-slate-300">
                  <span>Primary DNS: <strong className="text-sky-300">{activeCarrier.primaryDns}</strong></span>
                  <span>Alt DNS: <strong className="text-slate-400">{activeCarrier.secondaryDns}</strong></span>
                </div>
              </div>

              {/* Host Lines Section with Real-Time DoH Ping */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
                    Active {activeCarrier.name} Host Lines &amp; SNI Domains ({carrierHostLines.length})
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    Click "Use Host" to test in inspector
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {carrierHostLines.map((hl, idx) => {
                    const health = hostHealth[hl.domain];
                    return (
                      <div
                        key={hl.id || idx}
                        className="bg-slate-950/80 border border-slate-800 hover:border-sky-500/40 rounded-xl p-3 transition space-y-2 flex flex-col justify-between"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-1 mb-1">
                            <div className="flex items-center gap-1.5">
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-sky-950/60 text-sky-300 border border-sky-800/50">
                                {hl.category}
                              </span>
                              {hl.isCustom && (
                                <span className="px-1 py-0.2 rounded text-[8px] font-bold bg-amber-950 text-amber-300 border border-amber-800">
                                  AUTO-ADDED
                                </span>
                              )}
                            </div>

                            {/* Real-Time DoH Health Badge */}
                            {health?.status === 'active' && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-950/70 text-emerald-300 border border-emerald-700/50 flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                                {health.ips?.[0] || 'Active'} • {health.latencyMs}ms
                              </span>
                            )}
                            {health?.status === 'probing' && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono text-sky-400 bg-sky-950 animate-pulse border border-sky-800">
                                Probing DoH...
                              </span>
                            )}
                            {health?.status === 'offline' && (
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-mono text-rose-400 bg-rose-950/70 border border-rose-800/50">
                                Offline / No A-Record
                              </span>
                            )}
                            {!health && (
                              <span className="text-[10px] font-mono text-emerald-400 font-semibold">
                                Port {hl.recommendedPort} • {hl.tunnelMethod}
                              </span>
                            )}
                          </div>

                          <code className="text-xs font-mono font-bold text-white break-all block">
                            {hl.domain}
                          </code>
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {hl.protocols.map((proto, pIdx) => (
                              <span
                                key={pIdx}
                                className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-slate-900 text-slate-300 border border-slate-800"
                              >
                                {proto}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div className="flex items-center gap-1.5 pt-2 border-t border-slate-900 mt-2">
                          <button
                            type="button"
                            onClick={() => handleApplyHost(hl.domain)}
                            className="flex-1 py-1 px-2 rounded-lg bg-sky-500/20 hover:bg-sky-500/30 text-sky-200 text-xs font-bold border border-sky-500/40 cursor-pointer transition text-center"
                          >
                            Use Host
                          </button>
                          <button
                            type="button"
                            onClick={() => handleCopy(hl.domain, `hl-${idx}`)}
                            className="py-1 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 cursor-pointer transition"
                          >
                            {copiedKey === `hl-${idx}` ? 'Copied' : 'Copy'}
                          </button>
                          <button
                            type="button"
                            onClick={() => handleCopy(hl.samplePayload, `pl-${idx}`)}
                            className="py-1 px-2 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-300 text-xs font-semibold border border-indigo-500/30 cursor-pointer transition"
                            title="Copy standard HTTP [crlf] payload"
                          >
                            {copiedKey === `pl-${idx}` ? 'Copied' : 'Payload'}
                          </button>
                          {hl.isCustom && hl.id && (
                            <button
                              type="button"
                              onClick={(e) => handleRemoveCustomHost(hl.id!, e)}
                              className="py-1 px-1.5 text-rose-400 hover:text-rose-300 text-[10px]"
                              title="Remove custom host"
                            >
                              ✕
                            </button>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Carrier Templates */}
              <div className="space-y-2">
                <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
                  Verified {activeCarrier.name} Profile Files ({carrierTemplates.length})
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {carrierTemplates.map((tpl) => (
                    <div
                      key={tpl.id}
                      className="bg-slate-950/80 border border-indigo-950 hover:border-indigo-500/40 rounded-xl p-3 transition flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-center justify-between gap-1 mb-1">
                          <span className="font-bold text-xs text-white truncate">{tpl.title}</span>
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-indigo-950 text-indigo-300 border border-indigo-800/60">
                            {tpl.format}
                          </span>
                        </div>
                        <p className="text-[11px] text-slate-300 line-clamp-2">{tpl.description}</p>
                        <div className="flex items-center justify-between text-[10px] font-mono text-sky-400 mt-1">
                          <span>Protocol: {tpl.protocol}</span>
                          <span className="text-emerald-400 font-semibold">Expires: {tpl.expiryDate}</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-1.5 pt-2.5 mt-2 border-t border-slate-900">
                        <button
                          type="button"
                          onClick={() => handleApplyTemplate(tpl)}
                          className="flex-1 py-1.5 px-2.5 rounded-lg bg-gradient-to-r from-sky-600 to-indigo-600 hover:opacity-90 text-white text-xs font-bold cursor-pointer transition shadow-md shadow-sky-500/20 flex items-center justify-center gap-1"
                        >
                          <span>Inspect Live</span>
                          <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                          </svg>
                        </button>
                        <button
                          type="button"
                          onClick={() => handleDownloadFile(tpl)}
                          className="py-1.5 px-2.5 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 text-xs font-semibold border border-emerald-500/30 cursor-pointer transition"
                          title={`Download ${tpl.fileName}`}
                        >
                          {copiedKey === `dl-${tpl.id}` ? 'Downloaded!' : 'Download'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCopy(tpl.rawConfig, `tpl-${tpl.id}`)}
                          className="py-1.5 px-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 cursor-pointer transition"
                        >
                          {copiedKey === `tpl-${tpl.id}` ? 'Copied' : 'Copy'}
                        </button>
                        {tpl.isCustom && (
                          <button
                            type="button"
                            onClick={(e) => handleRemoveCustomFile(tpl.id, e)}
                            className="py-1.5 px-1.5 text-rose-400 hover:text-rose-300 text-xs"
                            title="Remove custom file"
                          >
                            ✕
                          </button>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: ALL ACTIVE VPN FILES & CLOUDS REPOSITORY */}
          {activeTab === 'all_files' && (
            <div className="space-y-3">
              {/* Filter by Format Bar */}
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <span className="text-xs font-bold text-slate-200">
                  Filter Active VPN Configurations ({filteredActiveFiles.length})
                </span>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {[
                    { id: 'all', label: 'All Formats' },
                    { id: '.nm', label: 'NetMod (.nm)' },
                    { id: '.v2box', label: 'V2Box (.v2box)' },
                    { id: '.hat', label: 'HA Tunnel (.hat)' },
                  ].map((f) => (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => setFormatFilter(f.id)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition cursor-pointer ${
                        formatFilter === f.id
                          ? 'bg-sky-500 text-slate-950 font-bold'
                          : 'bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800'
                      }`}
                    >
                      {f.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Grid of All Active VPN Files Across All Carriers */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                {filteredActiveFiles.map((file) => (
                  <div
                    key={file.id}
                    className="bg-slate-950/80 border border-slate-800 hover:border-sky-500/40 rounded-xl p-3 transition space-y-2 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-1 mb-1">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-900 text-slate-300 border border-slate-800">
                          {file.carrierName}
                        </span>
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-sky-950 text-sky-300 border border-sky-800/60">
                          {file.format}
                        </span>
                      </div>
                      <h3 className="text-xs font-extrabold text-white truncate">{file.title}</h3>
                      <p className="text-[11px] text-slate-400 line-clamp-1 mt-0.5">{file.description}</p>
                      <div className="flex items-center justify-between text-[10px] font-mono text-slate-400 mt-2 bg-slate-900/60 p-2 rounded-lg border border-slate-800/80">
                        <span>SNI: <strong className="text-sky-300">{file.hostLineUsed}</strong></span>
                        <span className="text-emerald-400 font-semibold">{file.protocol}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 pt-2 border-t border-slate-900">
                      <button
                        type="button"
                        onClick={() => handleApplyTemplate(file)}
                        className="flex-1 py-1.5 px-3 rounded-lg bg-sky-500/20 hover:bg-sky-500/30 text-sky-200 text-xs font-bold border border-sky-500/40 cursor-pointer transition text-center"
                      >
                        Inspect Live
                      </button>
                      <button
                        type="button"
                        onClick={() => handleDownloadFile(file)}
                        className="py-1.5 px-3 rounded-lg bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 text-xs font-semibold border border-emerald-500/30 cursor-pointer transition"
                      >
                        {copiedKey === `dl-${file.id}` ? 'Saved' : 'Download'}
                      </button>
                      <button
                        type="button"
                        onClick={() => handleCopy(file.rawConfig, `f-${file.id}`)}
                        className="py-1.5 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 cursor-pointer transition"
                      >
                        {copiedKey === `f-${file.id}` ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: DYNAMIC ADD & AUTO-INSPECT DRAWER */}
          {activeTab === 'add_new' && (
            <div className="bg-slate-950/70 border border-indigo-900/40 rounded-xl p-4 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
                <div>
                  <h3 className="text-xs sm:text-sm font-extrabold text-white flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-indigo-400 animate-pulse" />
                    <span>Add New Host Line, Config File or Cloud Subscription</span>
                  </h3>
                  <p className="text-[11px] text-slate-400 mt-0.5">
                    Newly added items are verified live, attached to carrier monitoring, and persisted in your browser
                  </p>
                </div>

                <div className="flex items-center gap-1.5 bg-slate-900 p-1 rounded-lg border border-slate-800">
                  <button
                    type="button"
                    onClick={() => setAddMode('host')}
                    className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer transition ${
                      addMode === 'host' ? 'bg-sky-500 text-slate-950' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    Host Line
                  </button>
                  <button
                    type="button"
                    onClick={() => setAddMode('file_cloud')}
                    className={`px-2.5 py-1 rounded text-xs font-bold cursor-pointer transition ${
                      addMode === 'file_cloud' ? 'bg-sky-500 text-slate-950' : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    File / Cloud URI
                  </button>
                </div>
              </div>

              {/* Mode A: Add Host Line */}
              {addMode === 'host' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        Domain / Host Line
                      </label>
                      <input
                        type="text"
                        value={newDomain}
                        onChange={(e) => setNewDomain(e.target.value)}
                        placeholder="e.g. portal.vodacom.co.tz or udsm.ac.tz"
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono placeholder-slate-500 focus:outline-none focus:border-sky-500"
                      />
                    </div>

                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        Target Mobile Carrier
                      </label>
                      <select
                        value={newCarrierId}
                        onChange={(e) => setNewCarrierId(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                      >
                        {TANZANIA_CARRIERS.map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.name} ({c.mccMnc})
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        Recommended Port
                      </label>
                      <input
                        type="number"
                        value={newPort}
                        onChange={(e) => setNewPort(parseInt(e.target.value) || 443)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white font-mono focus:outline-none focus:border-sky-500"
                      />
                    </div>

                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        Tunnel Method
                      </label>
                      <select
                        value={newTunnelMethod}
                        onChange={(e) => setNewTunnelMethod(e.target.value as any)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                      >
                        <option value="TLS / SNI Spoof">TLS / SNI Spoof</option>
                        <option value="CDN WebSocket">CDN WebSocket</option>
                        <option value="Direct HTTP Payload">Direct HTTP Payload</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        Category
                      </label>
                      <select
                        value={newCategory}
                        onChange={(e) => setNewCategory(e.target.value as any)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                      >
                        <option value="SelfCare & Portal">SelfCare &amp; Portal</option>
                        <option value="FinTech & M-Pesa">FinTech &amp; M-Pesa</option>
                        <option value="CDN Front">CDN Front</option>
                        <option value="Gateway">Gateway</option>
                      </select>
                    </div>
                  </div>

                  <div className="flex justify-end pt-2">
                    <button
                      type="button"
                      onClick={handleAddNewHost}
                      className="px-4 py-2 rounded-xl bg-gradient-to-r from-sky-600 to-indigo-600 hover:opacity-90 text-white text-xs font-bold cursor-pointer transition shadow-md shadow-sky-500/20"
                    >
                      Probe Live &amp; Add Host to Sync
                    </button>
                  </div>
                </div>
              )}

              {/* Mode B: Add File / Cloud Subscription */}
              {addMode === 'file_cloud' && (
                <div className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        Configuration Title / Alias
                      </label>
                      <input
                        type="text"
                        value={newFileTitle}
                        onChange={(e) => setNewFileTitle(e.target.value)}
                        placeholder="e.g. Vodacom VIP Cloud Tunnel"
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
                      />
                    </div>

                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        VPN Format
                      </label>
                      <select
                        value={newFileFormat}
                        onChange={(e) => setNewFileFormat(e.target.value as any)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                      >
                        <option value=".v2box">V2Box (.v2box / v2box://)</option>
                        <option value=".nm">NetMod Syna (.nm)</option>
                        <option value=".hat">HA Tunnel Plus (.hat)</option>
                        <option value=".hc">HTTP Custom (.hc)</option>
                        <option value=".tnl">OpenTunnel (.tnl)</option>
                      </select>
                    </div>

                    <div>
                      <label className="text-[11px] font-bold text-slate-300 block mb-1">
                        Associated Carrier
                      </label>
                      <select
                        value={newCarrierId}
                        onChange={(e) => setNewCarrierId(e.target.value)}
                        className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-sky-500"
                      >
                        {TANZANIA_CARRIERS.map((c) => (
                          <option key={c.id} value={c.id}>
                            {c.name}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="text-[11px] font-bold text-slate-300 block mb-1">
                      Raw Configuration String, URI or Cloud Subscription Link
                    </label>
                    <textarea
                      rows={3}
                      value={newFileRawConfig}
                      onChange={(e) => setNewFileRawConfig(e.target.value)}
                      placeholder="Paste vless://, vmess://, netmod://, .nm Base64, or Cloud UUID..."
                      className="w-full bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-xs text-white font-mono placeholder-slate-500 focus:outline-none focus:border-sky-500"
                    />
                  </div>

                  <div className="flex justify-end pt-1">
                    <button
                      type="button"
                      onClick={handleAddNewFile}
                      className="px-4 py-2 rounded-xl bg-gradient-to-r from-emerald-600 to-sky-600 hover:opacity-90 text-white text-xs font-bold cursor-pointer transition shadow-md shadow-emerald-500/20"
                    >
                      Auto-Inspect &amp; Add File to Repository
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
