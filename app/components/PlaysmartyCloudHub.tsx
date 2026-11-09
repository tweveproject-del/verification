'use client';

import React, { useState, useEffect } from 'react';

interface PlaysmartyStatus {
  code: string;
  fullUrl: string;
  active: boolean;
  status: 'active' | 'burned_or_expired' | 'http_error' | 'network_error';
  message: string;
  checkedAt: string;
  burnPolicy?: string;
  expiresAt?: number;
}

interface RecentCheck {
  code: string;
  status: 'active' | 'burned_or_expired';
  checkedAt: string;
}

interface PlaysmartyCloudHubProps {
  onLoadAndVerify: (url: string) => void;
  onUploadFileClick: () => void;
}

export default function PlaysmartyCloudHub({
  onLoadAndVerify,
  onUploadFileClick,
}: PlaysmartyCloudHubProps) {
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [inputCode, setInputCode] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(false);
  const [currentStatus, setCurrentStatus] = useState<PlaysmartyStatus | null>(null);
  const [recentChecks, setRecentChecks] = useState<RecentCheck[]>([]);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Expiration countdown in seconds for active links
  const [timeLeftSec, setTimeLeftSec] = useState<number | null>(null);

  // Load recent checks from localStorage
  useEffect(() => {
    try {
      const saved = localStorage.getItem('tweve_recent_playsmarty_checks');
      if (saved) {
        setRecentChecks(JSON.parse(saved));
      }
    } catch {}
  }, []);

  // Save recent checks to localStorage
  const saveRecentCheck = (code: string, status: 'active' | 'burned_or_expired') => {
    setRecentChecks(prev => {
      const filtered = prev.filter(c => c.code.toLowerCase() !== code.toLowerCase());
      const updated: RecentCheck[] = [
        { code, status, checkedAt: new Date().toLocaleTimeString() },
        ...filtered.slice(0, 7),
      ];
      try {
        localStorage.setItem('tweve_recent_playsmarty_checks', JSON.stringify(updated));
      } catch {}
      return updated;
    });
  };

  // Timer countdown hook
  useEffect(() => {
    if (!currentStatus?.active) {
      setTimeLeftSec(null);
      return;
    }
    // Set 30 minute default countdown if not provided
    let remaining = 30 * 60;
    setTimeLeftSec(remaining);
    const interval = setInterval(() => {
      remaining -= 1;
      if (remaining <= 0) {
        clearInterval(interval);
        setTimeLeftSec(0);
      } else {
        setTimeLeftSec(remaining);
      }
    }, 1000);
    return () => clearInterval(interval);
  }, [currentStatus]);

  const copyText = (key: string, text: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2500);
    }
  };

  const handleCheckStatus = async (overrideCode?: string) => {
    const raw = (overrideCode || inputCode).trim();
    if (!raw) return;

    let cleanCode = raw;
    const urlMatch = raw.match(/link\.playsmarty\.uk\/([a-zA-Z0-9_-]+)/i);
    if (urlMatch) {
      cleanCode = urlMatch[1];
    } else {
      cleanCode = cleanCode.replace(/[^a-zA-Z0-9_-]/g, '');
    }

    if (!cleanCode) return;

    setLoading(true);
    setCurrentStatus(null);

    try {
      // 1. Try local server-side API first
      let data: PlaysmartyStatus | null = null;
      try {
        const resp = await fetch(`/api/playsmarty?code=${encodeURIComponent(cleanCode)}`, {
          cache: 'no-store',
        });
        if (resp.ok) {
          data = await resp.json();
        }
      } catch {}

      // 2. Fallback to direct client fetch if server API is unavailable
      if (!data) {
        try {
          const directResp = await fetch(`https://link.playsmarty.uk/api/stats/${encodeURIComponent(cleanCode)}`, {
            cache: 'no-store',
          });
          if (directResp.ok) {
            const stats = await directResp.json();
            data = {
              code: cleanCode,
              fullUrl: `https://link.playsmarty.uk/${cleanCode}`,
              active: Boolean(stats.active),
              status: stats.active ? 'active' : 'burned_or_expired',
              message: stats.active
                ? 'Live & Active — Waiting to be opened'
                : 'Opened or Expired',
              checkedAt: new Date().toISOString(),
            };
          } else if (directResp.status === 404) {
            data = {
              code: cleanCode,
              fullUrl: `https://link.playsmarty.uk/${cleanCode}`,
              active: false,
              status: 'burned_or_expired',
              message: 'Opened or Expired — File already downloaded once or expired after 30 minutes.',
              checkedAt: new Date().toISOString(),
            };
          }
        } catch (e: any) {
          data = {
            code: cleanCode,
            fullUrl: `https://link.playsmarty.uk/${cleanCode}`,
            active: false,
            status: 'network_error',
            message: 'Could not connect directly to link.playsmarty.uk',
            checkedAt: new Date().toISOString(),
          };
        }
      }

      if (data) {
        setCurrentStatus(data);
        if (data.status === 'active' || data.status === 'burned_or_expired') {
          saveRecentCheck(data.code, data.status);
        }
      }
    } finally {
      setLoading(false);
    }
  };

  const formatTimer = (sec: number | null) => {
    if (sec === null) return '--:--';
    if (sec <= 0) return '00:00 (Expired)';
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  return (
    <div className="w-full bg-slate-900/90 border border-indigo-500/30 rounded-2xl p-4 sm:p-6 shadow-xl space-y-4">
      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-indigo-500/20 pb-3 flex-wrap gap-2">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-indigo-600 to-purple-600 flex items-center justify-center text-white font-black shadow-md shadow-indigo-500/20">
            <span>⚡</span>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-extrabold text-white text-sm sm:text-base tracking-wide">
                HTTP Custom Cloud Hub &middot; link.playsmarty.uk
              </h3>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-bold uppercase bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                Official Cloud Gateway
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Live status inspector, safe non-burning probe, and instant configuration verification.
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setIsExpanded(!isExpanded)}
          className="text-xs font-semibold px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition cursor-pointer"
        >
          {isExpanded ? 'Hide Hub ▲' : 'Show Hub ▼'}
        </button>
      </div>

      {isExpanded && (
        <div className="space-y-5 pt-1">
          {/* Input & Check Actions */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300 block">
              Enter Coldplay Shortlink or Shortcode:
            </label>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <div className="relative flex-1">
                <input
                  type="text"
                  value={inputCode}
                  onChange={e => setInputCode(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && handleCheckStatus()}
                  placeholder="e.g. loJXo5 or https://link.playsmarty.uk/loJXo5"
                  className="w-full px-4 py-2.5 rounded-xl bg-slate-950/80 border border-slate-700 focus:border-indigo-400 focus:outline-none text-slate-100 font-mono text-sm placeholder:text-slate-600"
                />
                {inputCode && (
                  <button
                    type="button"
                    onClick={() => setInputCode('')}
                    className="absolute right-3 top-2.5 text-slate-500 hover:text-slate-300 text-sm font-bold"
                  >
                    &times;
                  </button>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  disabled={loading || !inputCode.trim()}
                  onClick={() => handleCheckStatus()}
                  className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-bold text-xs sm:text-sm transition cursor-pointer flex items-center justify-center gap-1.5 shadow-md shadow-indigo-600/30"
                >
                  {loading ? (
                    <>
                      <span className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Probing...
                    </>
                  ) : (
                    <>
                      <span>🔍</span> Check Live Status
                    </>
                  )}
                </button>

                <button
                  type="button"
                  disabled={!inputCode.trim()}
                  onClick={() => onLoadAndVerify(`https://link.playsmarty.uk/${inputCode.replace(/.*link\.playsmarty\.uk\//i, '').trim()}`)}
                  className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 disabled:opacity-50 text-slate-950 font-black text-xs sm:text-sm transition cursor-pointer flex items-center justify-center gap-1.5 shadow-md shadow-emerald-500/20"
                >
                  <span>⚡</span> Verify Now
                </button>
              </div>
            </div>
            <p className="text-[11px] text-slate-400 flex items-center gap-1.5">
              <span>💡</span>
              <span>
                <strong>&quot;Check Live Status&quot;</strong> uses a zero-download probe that checks if the link is active <strong>WITHOUT burning it</strong>.
              </span>
            </p>
          </div>

          {/* Live Status Result Card */}
          {currentStatus && (
            <div
              className={`p-4 sm:p-5 rounded-2xl border transition-all ${
                currentStatus.active
                  ? 'bg-gradient-to-r from-emerald-950/40 via-slate-900/90 to-teal-950/40 border-emerald-500/50 shadow-emerald-950/40 shadow-xl'
                  : 'bg-gradient-to-r from-rose-950/40 via-slate-900/90 to-rose-950/30 border-rose-500/50 shadow-rose-950/40 shadow-xl'
              }`}
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-700/60 gap-3">
                <div className="flex items-center gap-2.5">
                  <span
                    className={`w-3.5 h-3.5 rounded-full ${
                      currentStatus.active
                        ? 'bg-emerald-400 shadow-md shadow-emerald-400 animate-pulse'
                        : 'bg-rose-500 shadow-md shadow-rose-500'
                    }`}
                  />
                  <div>
                    <h4 className="font-extrabold text-white text-sm sm:text-base">
                      {currentStatus.active ? '🟢 Link is LIVE & Active' : '🔴 Link is Opened or Expired'}
                    </h4>
                    <span className="font-mono text-xs text-indigo-300">
                      {currentStatus.fullUrl}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  {currentStatus.active && (
                    <div className="px-3 py-1 rounded-full bg-slate-950/90 border border-emerald-500/40 flex items-center gap-1.5 text-xs text-emerald-300 font-mono font-bold">
                      <span>⏱️ Est. TTL:</span>
                      <span>{formatTimer(timeLeftSec)}</span>
                    </div>
                  )}
                  <button
                    type="button"
                    onClick={() => copyText('fullLink', currentStatus.fullUrl)}
                    className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition cursor-pointer"
                  >
                    {copiedKey === 'fullLink' ? 'Copied!' : 'Copy Link'}
                  </button>
                </div>
              </div>

              {/* Status Details */}
              <div className="pt-3 text-xs space-y-3">
                <p className="text-slate-200 leading-relaxed">
                  {currentStatus.message}
                </p>

                {currentStatus.active ? (
                  <div className="p-3 rounded-xl bg-emerald-950/40 border border-emerald-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                    <div>
                      <span className="font-bold text-emerald-300 block">
                        Safe to Verify &amp; Capture:
                      </span>
                      <span className="text-slate-300 text-[11px]">
                        The file has not yet been consumed. Verify now to extract authentic SSH, SNI, and SlowDNS keys and save as Permanent Link.
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => onLoadAndVerify(currentStatus.fullUrl)}
                      className="px-4 py-2 rounded-xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-black text-xs shrink-0 transition cursor-pointer shadow-md shadow-emerald-500/30"
                    >
                      🚀 Verify &amp; Decrypt Config Now
                    </button>
                  </div>
                ) : (
                  <div className="p-3 rounded-xl bg-slate-950/70 border border-rose-500/30 space-y-2">
                    <span className="font-bold text-rose-300 block">
                      Why is this link burned?
                    </span>
                    <p className="text-slate-300 text-[11px] leading-relaxed">
                      Coldplay shortlinks strictly enforce <strong>&quot;Deleted the moment it is opened&quot;</strong> and auto-expire after <strong>30 minutes</strong>. Once HTTP Custom downloaded it or 30 minutes passed, the remote server erased the file.
                    </p>
                    <div className="flex items-center gap-2 pt-1 flex-wrap">
                      <button
                        type="button"
                        onClick={onUploadFileClick}
                        className="px-3 py-1.5 rounded-lg bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs transition cursor-pointer"
                      >
                        📁 Upload Original .hc File
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Quick Recent Checks Bar */}
          {recentChecks.length > 0 && (
            <div className="pt-1">
              <div className="flex items-center justify-between pb-1.5">
                <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                  Recently Inspected Playsmarty Shortlinks:
                </span>
                <button
                  type="button"
                  onClick={() => {
                    localStorage.removeItem('tweve_recent_playsmarty_checks');
                    setRecentChecks([]);
                  }}
                  className="text-[10px] text-slate-500 hover:text-slate-300"
                >
                  Clear History
                </button>
              </div>

              <div className="flex items-center gap-2 flex-wrap">
                {recentChecks.map(item => (
                  <div
                    key={item.code}
                    className="px-2.5 py-1 rounded-lg bg-slate-950/80 border border-slate-800 flex items-center gap-1.5 text-xs font-mono"
                  >
                    <span
                      className={`w-2 h-2 rounded-full ${
                        item.status === 'active' ? 'bg-emerald-400' : 'bg-rose-500'
                      }`}
                    />
                    <button
                      type="button"
                      onClick={() => {
                        setInputCode(item.code);
                        handleCheckStatus(item.code);
                      }}
                      className="text-slate-200 hover:text-indigo-300 font-bold"
                    >
                      {item.code}
                    </button>
                    <span className="text-[10px] text-slate-500">
                      ({item.status === 'active' ? 'Live' : 'Burned'})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
