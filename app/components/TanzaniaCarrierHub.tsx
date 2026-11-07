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

interface TanzaniaCarrierHubProps {
  onLoadConfig: (configContent: string) => void;
  onRunInspect?: () => void;
}

export default function TanzaniaCarrierHub({ onLoadConfig, onRunInspect }: TanzaniaCarrierHubProps) {
  const [activeTab, setActiveTab] = useState<'carrier' | 'all_files'>('carrier');
  const [selectedCarrierId, setSelectedCarrierId] = useState<string>('vodacom');
  const [formatFilter, setFormatFilter] = useState<string>('all');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [customHost, setCustomHost] = useState<string>('');
  const [generatedPayload, setGeneratedPayload] = useState<string | null>(null);

  // Auto-Sync and Live DoH Probe State
  const [autoSyncEnabled, setAutoSyncEnabled] = useState<boolean>(false);
  const [isSyncing, setIsSyncing] = useState<boolean>(false);
  const [lastSyncedTime, setLastSyncedTime] = useState<string | null>(null);
  const [secondsUntilNextSync, setSecondsUntilNextSync] = useState<number>(45);
  const [hostHealth, setHostHealth] = useState<Record<string, HostHealthState>>({});

  const activeCarrier: TanzaniaCarrier =
    TANZANIA_CARRIERS.find((c) => c.id === selectedCarrierId) || TANZANIA_CARRIERS[0];

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

  const handleGenerateCustomPayload = () => {
    if (!customHost.trim()) return;
    const clean = customHost.trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    const payload = `GET / HTTP/1.1[crlf]Host: ${clean}[crlf]X-Online-Host: ${clean}[crlf]X-Forward-Host: ${clean}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]`;
    setGeneratedPayload(payload);
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

  // Batch Auto-Sync All Hosts
  const runBatchSync = async () => {
    setIsSyncing(true);
    const allDomains = Array.from(
      new Set(TANZANIA_CARRIERS.flatMap((c) => c.hostLines.map((h) => h.domain)))
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
  }, [autoSyncEnabled]);

  // Filtered list of all active files
  const filteredActiveFiles = ALL_ACTIVE_VPN_FILES.filter((f) => {
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
          {/* Mode Switcher Tabs: Carrier View vs All Active Files Repository */}
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
                {ALL_ACTIVE_VPN_FILES.length} Files Active
              </span>
            </button>
          </div>

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
                      onClick={() => {
                        setSelectedCarrierId(carrier.id);
                        setGeneratedPayload(null);
                      }}
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
                    Active {activeCarrier.name} Host Lines &amp; SNI Domains ({activeCarrier.hostLines.length})
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    Click "Use Host" to test in inspector
                  </span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
                  {activeCarrier.hostLines.map((hl, idx) => {
                    const health = hostHealth[hl.domain];
                    return (
                      <div
                        key={idx}
                        className="bg-slate-950/80 border border-slate-800 hover:border-sky-500/40 rounded-xl p-3 transition space-y-2 flex flex-col justify-between"
                      >
                        <div>
                          <div className="flex items-center justify-between gap-1 mb-1">
                            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-sky-950/60 text-sky-300 border border-sky-800/50">
                              {hl.category}
                            </span>

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
                  Verified {activeCarrier.name} Profile Files ({activeCarrier.templates.length})
                </span>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {activeCarrier.templates.map((tpl) => (
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

          {/* Custom Host Line & Payload Generator Drawer */}
          <div className="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3 space-y-2">
            <div className="flex items-center justify-between text-xs font-bold text-slate-300">
              <span>Custom Tanzania Host Line &amp; Payload Formatter</span>
              <span className="text-[10px] font-mono text-slate-400">RFC 2616 CRLF Compliant</span>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={customHost}
                onChange={(e) => setCustomHost(e.target.value)}
                placeholder="e.g. portal.vodacom.co.tz, udsm.ac.tz, or airtel.co.tz"
                className="flex-1 bg-slate-900 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-white font-mono placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
              <button
                type="button"
                onClick={handleGenerateCustomPayload}
                className="px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-bold cursor-pointer transition"
              >
                Generate Payload
              </button>
            </div>

            {generatedPayload && (
              <div className="space-y-1.5 mt-2">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] uppercase font-bold text-slate-400">Generated WebSocket Payload</span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => handleApplyHost(generatedPayload)}
                      className="text-[10px] text-sky-400 hover:text-sky-300 font-semibold"
                    >
                      Apply to Inspector
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy(generatedPayload, 'customPl')}
                      className="text-[10px] text-emerald-400 hover:text-emerald-300 font-semibold"
                    >
                      {copiedKey === 'customPl' ? 'Copied!' : 'Copy Payload'}
                    </button>
                  </div>
                </div>
                <pre className="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-emerald-300 whitespace-pre-wrap break-all">
                  {generatedPayload}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
