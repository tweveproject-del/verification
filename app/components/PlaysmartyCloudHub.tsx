'use client';

import React, { useState, useEffect, useRef } from 'react';

export interface PlaysmartyCloudEntry {
  code: string;
  fullUrl: string;
  label: string;
  protocol: 'v2ray' | 'ssh' | 'slowdns' | 'auto';
  carrier?: string;
  addedAt: string;
  status: 'active' | 'burned_or_expired' | 'unverified';
  statusMessage?: string;
  lastChecked?: string;
  expiresAt?: number;
}

interface PlaysmartyStatus {
  code: string;
  fullUrl: string;
  active: boolean;
  status: 'active' | 'burned_or_expired' | 'http_error' | 'network_error';
  message: string;
  checkedAt: string;
  burnPolicy?: string;
}

interface PlaysmartyCloudHubProps {
  onLoadAndVerify: (url: string, protocolMode?: 'v2ray' | 'ssh' | 'slowdns' | 'auto') => void;
  onUploadFileClick: () => void;
}

const DEFAULT_PRESET_CLOUDS: PlaysmartyCloudEntry[] = [
  {
    code: 'ZQxBkl',
    fullUrl: 'https://link.playsmarty.uk/ZQxBkl',
    label: 'Live VIP V2Ray Xray-Core (Mode #9)',
    protocol: 'v2ray',
    carrier: 'Vodacom / Tigo / Airtel',
    addedAt: 'Live Now',
    status: 'active',
    statusMessage: 'Active in Playsmarty temporary storage — Ready to verify & download',
    expiresAt: Date.now() + 30 * 60 * 1000,
  },
  {
    code: 'MlsZfm',
    fullUrl: 'https://link.playsmarty.uk/MlsZfm',
    label: 'Playsmarty Cloud Outbound (#MlsZfm)',
    protocol: 'v2ray',
    carrier: 'Tanzania Multi-ISP',
    addedAt: 'Recently Created',
    status: 'unverified',
    statusMessage: 'Playsmarty shortlink',
  },
  {
    code: 'klSGZo',
    fullUrl: 'https://link.playsmarty.uk/klSGZo',
    label: 'VIP Xray-Core VLESS (HTTP Custom)',
    protocol: 'v2ray',
    carrier: 'Vodacom Tanzania',
    addedAt: 'Verified Config',
    status: 'active',
    statusMessage: 'Mode #9 (V2Ray Xray-Core • libaio.so)',
  },
  {
    code: 'loJXo5',
    fullUrl: 'https://link.playsmarty.uk/loJXo5',
    label: 'HTTP Custom Cloud Direct',
    protocol: 'auto',
    carrier: 'Universal Multi-ISP',
    addedAt: 'Live Stream',
    status: 'unverified',
    statusMessage: 'Playsmarty shortlink',
  },
];

export default function PlaysmartyCloudHub({
  onLoadAndVerify,
  onUploadFileClick,
}: PlaysmartyCloudHubProps) {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [inputCode, setInputCode] = useState<string>('');
  const [inputLabel, setInputLabel] = useState<string>('');
  const [inputCarrier, setInputCarrier] = useState<string>('Universal Multi-ISP');
  const [selectedProtocol, setSelectedProtocol] = useState<'v2ray' | 'ssh' | 'slowdns' | 'auto'>('v2ray');
  const [loading, setLoading] = useState<boolean>(false);
  const [uploading, setUploading] = useState<boolean>(false);
  const [probingAll, setProbingAll] = useState<boolean>(false);
  const [currentStatus, setCurrentStatus] = useState<PlaysmartyStatus | null>(null);
  const [cloudStream, setCloudStream] = useState<PlaysmartyCloudEntry[]>(DEFAULT_PRESET_CLOUDS);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<'all' | 'v2ray' | 'ssh' | 'active'>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [showAddForm, setShowAddForm] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'stream' | 'create'>('stream');

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Load cloud stream from localStorage on mount
  useEffect(() => {
    try {
      const saved = localStorage.getItem('tweve_playsmarty_cloud_stream');
      if (saved) {
        const parsed: PlaysmartyCloudEntry[] = JSON.parse(saved);
        if (Array.isArray(parsed) && parsed.length > 0) {
          const merged = [...parsed];
          for (const def of DEFAULT_PRESET_CLOUDS) {
            if (!merged.some(m => m.code.toLowerCase() === def.code.toLowerCase())) {
              merged.push(def);
            }
          }
          setCloudStream(merged);
        }
      }
    } catch {}
  }, []);

  // Save cloud stream to localStorage
  const saveStream = (newStream: PlaysmartyCloudEntry[]) => {
    setCloudStream(newStream);
    try {
      localStorage.setItem('tweve_playsmarty_cloud_stream', JSON.stringify(newStream));
    } catch {}
  };

  const copyText = (key: string, text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2500);
    }
  };

  const extractCleanCode = (raw: string): string => {
    const trimmed = raw.trim();
    const urlMatch = trimmed.match(/link\.playsmarty\.uk\/([a-zA-Z0-9_-]+)/i);
    if (urlMatch) return urlMatch[1];
    return trimmed.replace(/[^a-zA-Z0-9_-]/g, '');
  };

  // Check live status of an individual shortcode
  const probeStatus = async (code: string): Promise<PlaysmartyStatus> => {
    const cleanCode = extractCleanCode(code);
    const fullUrl = `https://link.playsmarty.uk/${cleanCode}`;

    // 1. Try local server-side API
    try {
      const resp = await fetch(`/api/playsmarty?code=${encodeURIComponent(cleanCode)}`, {
        cache: 'no-store',
      });
      if (resp.ok) {
        const data = await resp.json();
        return {
          code: cleanCode,
          fullUrl,
          active: Boolean(data.active),
          status: data.status || (data.active ? 'active' : 'burned_or_expired'),
          message: data.message || (data.active ? 'Live & Active in Temporary Storage' : 'Burned / Expired on Playsmarty'),
          checkedAt: new Date().toISOString(),
          burnPolicy: data.burnPolicy,
        };
      }
    } catch {}

    // 2. Direct client fallback
    try {
      const directResp = await fetch(`https://link.playsmarty.uk/api/stats/${encodeURIComponent(cleanCode)}`, {
        cache: 'no-store',
      });
      if (directResp.ok) {
        const stats = await directResp.json();
        return {
          code: cleanCode,
          fullUrl,
          active: Boolean(stats.active),
          status: stats.active ? 'active' : 'burned_or_expired',
          message: stats.active ? 'Live & Active in Playsmarty Storage' : 'Opened or Expired (30m limit)',
          checkedAt: new Date().toISOString(),
        };
      } else if (directResp.status === 404) {
        return {
          code: cleanCode,
          fullUrl,
          active: false,
          status: 'burned_or_expired',
          message: 'Expired from Playsmarty Storage — Downloaded once or timed out (30 mins)',
          checkedAt: new Date().toISOString(),
        };
      }
    } catch {}

    return {
      code: cleanCode,
      fullUrl,
      active: false,
      status: 'network_error',
      message: 'Could not connect directly to link.playsmarty.uk',
      checkedAt: new Date().toISOString(),
    };
  };

  // Handle single probe from input
  const handleCheckStatus = async (overrideCode?: string) => {
    const raw = (overrideCode || inputCode).trim();
    if (!raw) return;
    const cleanCode = extractCleanCode(raw);
    if (!cleanCode) return;

    setLoading(true);
    setCurrentStatus(null);

    try {
      const statusData = await probeStatus(cleanCode);
      setCurrentStatus(statusData);

      // Update the stream entry if present
      saveStream(
        cloudStream.map(entry =>
          entry.code.toLowerCase() === cleanCode.toLowerCase()
            ? {
                ...entry,
                status: statusData.active ? 'active' : 'burned_or_expired',
                statusMessage: statusData.message,
                lastChecked: new Date().toLocaleTimeString(),
              }
            : entry
        )
      );
    } finally {
      setLoading(false);
    }
  };

  // Directly create cloud link by uploading .hc file to link.playsmarty.uk
  const handleDirectFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    try {
      const reader = new FileReader();
      reader.onload = async () => {
        const base64 = (reader.result as string).split(',')[1];
        if (!base64) return;

        const resp = await fetch('/api/playsmarty', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            rawBase64: base64,
            filename: file.name,
            alias: inputLabel ? inputLabel.toLowerCase().replace(/[^a-z0-9_-]/g, '').slice(0, 20) : undefined,
          }),
        });

        if (resp.ok) {
          const resData = await resp.json();
          const cleanCode = resData.code;
          const fullUrl = resData.shortUrl || `https://link.playsmarty.uk/${cleanCode}`;

          const newEntry: PlaysmartyCloudEntry = {
            code: cleanCode,
            fullUrl,
            label: inputLabel.trim() || `Playsmarty Cloud (#${cleanCode})`,
            protocol: selectedProtocol,
            carrier: inputCarrier.trim() || 'Universal Multi-ISP',
            addedAt: 'Just Now',
            status: 'active',
            statusMessage: 'Live & Active in Playsmarty temporary storage (Ready to verify & connect)',
            expiresAt: resData.expiresAt || (Date.now() + 30 * 60 * 1000),
          };

          const updated = [
            newEntry,
            ...cloudStream.filter(c => c.code.toLowerCase() !== cleanCode.toLowerCase()),
          ];
          saveStream(updated);
          setActiveTab('stream');
          setInputCode('');
          setInputLabel('');

          // Trigger inspector verification immediately
          onLoadAndVerify(fullUrl, selectedProtocol);
        } else {
          alert('Failed to upload configuration to link.playsmarty.uk');
        }
        setUploading(false);
      };
      reader.readAsDataURL(file);
    } catch {
      setUploading(false);
    }
  };

  // Add a new cloud to the persistent stream
  const handleAddCloudToStream = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const cleanCode = extractCleanCode(inputCode);
    if (!cleanCode) return;

    const fullUrl = `https://link.playsmarty.uk/${cleanCode}`;
    const newEntry: PlaysmartyCloudEntry = {
      code: cleanCode,
      fullUrl,
      label: inputLabel.trim() || `Playsmarty Cloud #${cleanCode}`,
      protocol: selectedProtocol,
      carrier: inputCarrier.trim() || 'Universal Multi-ISP',
      addedAt: new Date().toLocaleDateString(),
      status: 'unverified',
      statusMessage: 'Added to stream',
    };

    const updated = [
      newEntry,
      ...cloudStream.filter(c => c.code.toLowerCase() !== cleanCode.toLowerCase()),
    ];
    saveStream(updated);
    setInputCode('');
    setInputLabel('');
    setShowAddForm(false);

    // Auto-probe the newly added link
    handleCheckStatus(cleanCode);
  };

  // Batch probe all clouds in stream
  const handleProbeAll = async () => {
    setProbingAll(true);
    try {
      const updated = await Promise.all(
        cloudStream.map(async entry => {
          try {
            const res = await probeStatus(entry.code);
            return {
              ...entry,
              status: (res.active ? 'active' : 'burned_or_expired') as 'active' | 'burned_or_expired',
              statusMessage: res.message,
              lastChecked: new Date().toLocaleTimeString(),
            };
          } catch {
            return entry;
          }
        })
      );
      saveStream(updated);
    } finally {
      setProbingAll(false);
    }
  };

  // Remove a cloud from stream
  const handleRemoveCloud = (code: string) => {
    const updated = cloudStream.filter(c => c.code.toLowerCase() !== code.toLowerCase());
    saveStream(updated);
  };

  // Copy full stream summary
  const handleCopyAllClouds = () => {
    const summary = cloudStream
      .map(
        (c, idx) =>
          `${idx + 1}. [${c.label}] ${c.fullUrl} • Protocol: ${c.protocol.toUpperCase()} • Status: ${c.status.toUpperCase()}`
      )
      .join('\n');
    copyText('copyAllClouds', summary);
  };

  // Generate permanent share link for this verification page
  const getPermanentShareLink = (code: string) => {
    const base = typeof window !== 'undefined' ? window.location.origin : '';
    return `${base}/?cloud=${encodeURIComponent(`https://link.playsmarty.uk/${code}`)}`;
  };

  // Filter and search logic
  const filteredClouds = cloudStream.filter(entry => {
    const matchesSearch =
      entry.code.toLowerCase().includes(searchQuery.toLowerCase()) ||
      entry.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (entry.carrier && entry.carrier.toLowerCase().includes(searchQuery.toLowerCase()));

    if (!matchesSearch) return false;
    if (activeFilter === 'v2ray') return entry.protocol === 'v2ray';
    if (activeFilter === 'ssh') return entry.protocol === 'ssh';
    if (activeFilter === 'active') return entry.status === 'active';
    return true;
  });

  const activeCount = cloudStream.filter(c => c.status === 'active').length;

  return (
    <div className="w-full bg-slate-900/90 border border-indigo-500/30 rounded-2xl p-4 sm:p-6 shadow-2xl space-y-5">
      {/* Hidden File Input for Direct Upload */}
      <input
        type="file"
        ref={fileInputRef}
        onChange={handleDirectFileUpload}
        accept=".hc"
        className="hidden"
      />

      {/* 1. Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-indigo-500/20 pb-4 gap-3">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-indigo-600 via-purple-600 to-cyan-500 flex items-center justify-center text-white font-black text-xl shadow-lg shadow-indigo-500/30 shrink-0">
            <span>☁️</span>
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="font-extrabold text-white text-base sm:text-lg tracking-wide">
                Playsmarty Cloud Stream &middot; link.playsmarty.uk
              </h3>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-black uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                {cloudStream.length} Active &amp; Archived Clouds
              </span>
              {activeCount > 0 && (
                <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  {activeCount} Live in Storage
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Live feed of all cloud configs created on <code className="text-cyan-300">link.playsmarty.uk</code> temporary storage. Share, verify, and preserve without expiration.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Create / Upload Cloud Button */}
          <button
            type="button"
            onClick={() => {
              setActiveTab('create');
              setShowAddForm(true);
            }}
            className="px-3.5 py-1.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-black text-xs transition cursor-pointer shadow-md shadow-cyan-500/20 flex items-center gap-1.5"
          >
            <span>⚡ Create Cloud Link</span>
          </button>

          {/* Add Link Button */}
          <button
            type="button"
            onClick={() => {
              setActiveTab('stream');
              setShowAddForm(!showAddForm);
            }}
            className="px-3.5 py-1.5 rounded-xl bg-indigo-600/80 hover:bg-indigo-600 text-white font-bold text-xs transition cursor-pointer border border-indigo-500/40 flex items-center gap-1.5"
          >
            <span>{showAddForm && activeTab === 'stream' ? '✕ Close Form' : '＋ Add Existing Code'}</span>
          </button>

          <button
            type="button"
            onClick={handleCopyAllClouds}
            className="px-3 py-1.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs transition cursor-pointer border border-slate-700 flex items-center gap-1.5"
            title="Copy all cloud links and descriptions to clipboard"
          >
            <span>{copiedKey === 'copyAllClouds' ? '✓ Copied Stream!' : '📋 Share All'}</span>
          </button>

          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-xs font-semibold px-3 py-1.5 rounded-xl bg-slate-800/80 hover:bg-slate-700 text-slate-400 hover:text-white transition cursor-pointer"
          >
            {isExpanded ? 'Hide ▲' : 'Show ▼'}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="space-y-5">
          {/* 2. Direct Cloud Creator / Link Register Drawer */}
          {showAddForm && (
            <div className="p-4 sm:p-5 rounded-2xl bg-gradient-to-br from-indigo-950/50 via-slate-950/90 to-purple-950/50 border border-indigo-500/40 space-y-4 shadow-2xl animate-in fade-in duration-200">
              {/* Creator Mode Switcher Tabs */}
              <div className="flex items-center justify-between pb-3 border-b border-indigo-500/20 flex-wrap gap-2">
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setActiveTab('create')}
                    className={`px-3 py-1.5 rounded-xl text-xs font-bold transition cursor-pointer flex items-center gap-1.5 ${
                      activeTab === 'create'
                        ? 'bg-gradient-to-r from-cyan-500 to-indigo-500 text-slate-950 shadow-md'
                        : 'bg-slate-900 text-slate-400 hover:text-white'
                    }`}
                  >
                    <span>⚡ Upload .hc to Playsmarty Storage</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveTab('stream')}
                    className={`px-3 py-1.5 rounded-xl text-xs font-bold transition cursor-pointer flex items-center gap-1.5 ${
                      activeTab === 'stream'
                        ? 'bg-gradient-to-r from-indigo-500 to-purple-600 text-white shadow-md'
                        : 'bg-slate-900 text-slate-400 hover:text-white'
                    }`}
                  >
                    <span>＋ Add Code / Link Created Elsewhere</span>
                  </button>
                </div>
                <button
                  type="button"
                  onClick={() => setShowAddForm(false)}
                  className="text-xs text-slate-400 hover:text-white p-1"
                >
                  ✕ Close
                </button>
              </div>

              {activeTab === 'create' ? (
                /* Tab 1: Upload .hc to link.playsmarty.uk */
                <div className="space-y-3.5">
                  <div className="p-4 rounded-xl bg-slate-950/70 border border-dashed border-indigo-500/50 text-center space-y-2">
                    <div className="text-2xl">📤</div>
                    <div>
                      <h4 className="text-sm font-extrabold text-white">
                        Upload .hc Configuration to link.playsmarty.uk Temporary Storage
                      </h4>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Instantly generates a live active shortlink (e.g. <code className="text-cyan-300">link.playsmarty.uk/XYZ</code>) and adds it to your live stream with full verification.
                      </p>
                    </div>

                    <div className="pt-2 flex items-center justify-center gap-3 flex-wrap">
                      <button
                        type="button"
                        disabled={uploading}
                        onClick={() => fileInputRef.current?.click()}
                        className="px-5 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-indigo-500 hover:from-cyan-400 hover:to-indigo-400 disabled:opacity-50 text-slate-950 font-black text-xs transition cursor-pointer shadow-lg shadow-cyan-500/20 flex items-center gap-2"
                      >
                        {uploading ? (
                          <>
                            <span className="w-3.5 h-3.5 border-2 border-slate-950/30 border-t-slate-950 rounded-full animate-spin" />
                            <span>Uploading to Playsmarty...</span>
                          </>
                        ) : (
                          <>
                            <span>📁</span> Choose .hc File to Upload
                          </>
                        )}
                      </button>
                    </div>
                  </div>
                </div>
              ) : (
                /* Tab 2: Add Existing Code */
                <form onSubmit={handleAddCloudToStream} className="space-y-3.5">
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                    <div className="sm:col-span-2 space-y-1">
                      <label className="text-[11px] font-bold text-slate-300 block">
                        Shortlink or Code: <span className="text-rose-400">*</span>
                      </label>
                      <input
                        type="text"
                        required
                        value={inputCode}
                        onChange={e => setInputCode(e.target.value)}
                        placeholder="e.g. MlsZfm, ZQxBkl, or https://link.playsmarty.uk/MlsZfm"
                        className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 focus:border-indigo-400 focus:outline-none text-slate-100 font-mono text-xs placeholder:text-slate-600"
                      />
                    </div>

                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-slate-300 block">
                        Protocol Mode:
                      </label>
                      <select
                        value={selectedProtocol}
                        onChange={e => setSelectedProtocol(e.target.value as any)}
                        className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-slate-200 font-bold text-xs focus:outline-none focus:border-indigo-400 cursor-pointer"
                      >
                        <option value="v2ray">⚡ V2Ray (Xray-Core)</option>
                        <option value="ssh">🔐 SSH Tunnel</option>
                        <option value="slowdns">📡 SlowDNS (DNSTT)</option>
                        <option value="auto">🔄 Auto Detect</option>
                      </select>
                    </div>

                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-slate-300 block">
                        Config Description / Tag:
                      </label>
                      <input
                        type="text"
                        value={inputLabel}
                        onChange={e => setInputLabel(e.target.value)}
                        placeholder="e.g. Vodacom 5G Fast Xray VLESS"
                        className="w-full px-3.5 py-2 rounded-xl bg-slate-950 border border-slate-700 focus:border-indigo-400 focus:outline-none text-slate-100 text-xs placeholder:text-slate-600"
                      />
                    </div>

                    <div className="space-y-1">
                      <label className="text-[11px] font-bold text-slate-300 block">
                        Target Carrier / Network:
                      </label>
                      <select
                        value={inputCarrier}
                        onChange={e => setInputCarrier(e.target.value)}
                        className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-slate-200 text-xs focus:outline-none focus:border-indigo-400 cursor-pointer"
                      >
                        <option value="Universal Multi-ISP">Universal Multi-ISP</option>
                        <option value="Vodacom Tanzania">Vodacom Tanzania</option>
                        <option value="Airtel Tanzania">Airtel Tanzania</option>
                        <option value="Tigo Tanzania">Tigo Tanzania</option>
                        <option value="Halotel Tanzania">Halotel Tanzania</option>
                      </select>
                    </div>

                    <div className="flex items-end">
                      <button
                        type="submit"
                        disabled={!inputCode.trim()}
                        className="w-full py-2 px-4 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 disabled:opacity-50 text-slate-950 font-black text-xs transition cursor-pointer shadow-md shadow-emerald-500/20"
                      >
                        🚀 Add &amp; Check Storage
                      </button>
                    </div>
                  </div>
                </form>
              )}
            </div>
          )}

          {/* 3. Stream Controls: Filter & Search Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-2xl bg-slate-950/70 border border-slate-800">
            {/* Filter Pills */}
            <div className="flex items-center gap-1.5 overflow-x-auto no-scrollbar">
              {[
                { id: 'all', label: `All (${cloudStream.length})` },
                { id: 'active', label: `🟢 Live in Storage (${cloudStream.filter(c => c.status === 'active').length})` },
                { id: 'v2ray', label: `⚡ V2Ray (${cloudStream.filter(c => c.protocol === 'v2ray').length})` },
                { id: 'ssh', label: `🔐 SSH (${cloudStream.filter(c => c.protocol === 'ssh').length})` },
              ].map(f => (
                <button
                  key={f.id}
                  type="button"
                  onClick={() => setActiveFilter(f.id as any)}
                  className={`px-3 py-1 rounded-lg text-xs font-bold transition whitespace-nowrap cursor-pointer ${
                    activeFilter === f.id
                      ? 'bg-indigo-500 text-white shadow-sm'
                      : 'bg-slate-900 hover:bg-slate-800 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>

            {/* Search Input & Probe All Action */}
            <div className="flex items-center gap-2">
              <div className="relative">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  placeholder="Search code or name..."
                  className="w-40 sm:w-56 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-indigo-400"
                />
                {searchQuery && (
                  <button
                    type="button"
                    onClick={() => setSearchQuery('')}
                    className="absolute right-2 top-1.5 text-slate-500 hover:text-slate-300 text-xs font-bold"
                  >
                    ✕
                  </button>
                )}
              </div>

              <button
                type="button"
                disabled={probingAll}
                onClick={handleProbeAll}
                className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-xs font-bold text-cyan-300 border border-cyan-500/30 transition cursor-pointer flex items-center gap-1.5 shrink-0"
                title="Run non-burning live status checks across all registered cloud links"
              >
                {probingAll ? (
                  <>
                    <span className="w-3 h-3 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin" />
                    <span>Checking...</span>
                  </>
                ) : (
                  <>
                    <span>🔄</span> Check Storage Status
                  </>
                )}
              </button>
            </div>
          </div>

          {/* 4. Cloud Stream Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3.5">
            {filteredClouds.map(entry => {
              const isLive = entry.status === 'active';
              const isBurned = entry.status === 'burned_or_expired';

              return (
                <div
                  key={entry.code}
                  className={`p-4 rounded-2xl border transition-all space-y-3 bg-gradient-to-b ${
                    isLive
                      ? 'from-emerald-950/25 via-slate-950/90 to-slate-900/90 border-emerald-500/40 shadow-lg shadow-emerald-950/20'
                      : isBurned
                      ? 'from-rose-950/20 via-slate-950/90 to-slate-900/90 border-slate-800'
                      : 'from-slate-900/90 to-slate-950/90 border-slate-800 hover:border-indigo-500/40'
                  }`}
                >
                  {/* Card Top: Badges & Remove */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-1.5 flex-wrap">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-black uppercase flex items-center gap-1 ${
                          isLive
                            ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            : isBurned
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                            : 'bg-slate-800 text-slate-400 border border-slate-700'
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            isLive
                              ? 'bg-emerald-400 animate-pulse'
                              : isBurned
                              ? 'bg-rose-400'
                              : 'bg-slate-500'
                          }`}
                        />
                        {isLive ? 'LIVE IN STORAGE' : isBurned ? 'EXPIRED' : 'READY'}
                      </span>

                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/15 text-indigo-300 border border-indigo-500/25">
                        {entry.protocol === 'v2ray' ? '⚡ V2Ray' : '🔐 SSH'}
                      </span>

                      {entry.carrier && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800/80 text-slate-300 truncate max-w-[110px]">
                          {entry.carrier}
                        </span>
                      )}
                    </div>

                    <button
                      type="button"
                      onClick={() => handleRemoveCloud(entry.code)}
                      className="text-slate-600 hover:text-rose-400 text-xs transition cursor-pointer p-1"
                      title="Remove from list"
                    >
                      ✕
                    </button>
                  </div>

                  {/* Card Mid: Title & Link */}
                  <div className="space-y-1">
                    <h4 className="font-extrabold text-white text-sm truncate" title={entry.label}>
                      {entry.label}
                    </h4>
                    <div className="flex items-center justify-between gap-2 bg-slate-950 p-2 rounded-xl border border-slate-800/80">
                      <span className="font-mono text-cyan-300 font-bold text-xs truncate">
                        https://link.playsmarty.uk/{entry.code}
                      </span>
                      <button
                        type="button"
                        onClick={() => copyText(`link_${entry.code}`, entry.fullUrl)}
                        className="text-[10px] px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 shrink-0 cursor-pointer"
                      >
                        {copiedKey === `link_${entry.code}` ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  {/* Card Status Description */}
                  {entry.statusMessage && (
                    <p className="text-[11px] text-slate-400 leading-tight">
                      {entry.statusMessage}
                    </p>
                  )}

                  {/* Card Bottom: Action Buttons */}
                  <div className="pt-1 grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => onLoadAndVerify(entry.fullUrl, entry.protocol)}
                      className="w-full py-2 px-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-black text-xs transition cursor-pointer flex items-center justify-center gap-1 shadow-md shadow-emerald-500/20"
                    >
                      <span>⚡</span> Verify Now
                    </button>

                    <button
                      type="button"
                      onClick={() => copyText(`perm_${entry.code}`, getPermanentShareLink(entry.code))}
                      className="w-full py-2 px-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 font-bold text-xs transition cursor-pointer border border-slate-700 flex items-center justify-center gap-1"
                      title="Share a permanent link that opens and verifies this config directly"
                    >
                      <span>{copiedKey === `perm_${entry.code}` ? '✓ Copied!' : '🔗 Share Link'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {filteredClouds.length === 0 && (
            <div className="p-8 text-center rounded-2xl bg-slate-950/50 border border-slate-800 space-y-2">
              <span className="text-2xl">🔍</span>
              <p className="text-xs text-slate-400 font-medium">
                No cloud configurations matched your search.
              </p>
              <button
                type="button"
                onClick={() => {
                  setSearchQuery('');
                  setActiveFilter('all');
                }}
                className="text-xs text-indigo-400 hover:underline cursor-pointer"
              >
                Reset filters
              </button>
            </div>
          )}

          {/* 5. Safe Preservation Footer Notice */}
          <div className="p-3.5 rounded-xl bg-indigo-950/30 border border-indigo-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-300">
            <div className="flex items-center gap-2">
              <span className="text-base shrink-0">🛡️</span>
              <span>
                <strong>Permanent Preservation:</strong> When you create or verify clouds here, the system preserves their architecture permanently in your verification stream so they never expire after 30 minutes.
              </span>
            </div>
            <button
              type="button"
              onClick={onUploadFileClick}
              className="px-3 py-1.5 rounded-lg bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/30 font-bold shrink-0 cursor-pointer"
            >
              📁 Upload Backup .hc File
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
