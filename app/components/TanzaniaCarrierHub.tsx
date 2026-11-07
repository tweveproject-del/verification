'use client';

import React, { useState } from 'react';
import { TANZANIA_CARRIERS, TanzaniaCarrier, TanzaniaHostLine, TanzaniaVerifiedTemplate } from '../tanzania-carriers';

interface TanzaniaCarrierHubProps {
  onLoadConfig: (configContent: string) => void;
  onRunInspect?: () => void;
}

export default function TanzaniaCarrierHub({ onLoadConfig, onRunInspect }: TanzaniaCarrierHubProps) {
  const [selectedCarrierId, setSelectedCarrierId] = useState<string>('vodacom');
  const [copiedDomain, setCopiedDomain] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(true);
  const [customHost, setCustomHost] = useState<string>('');
  const [generatedPayload, setGeneratedPayload] = useState<string | null>(null);

  const activeCarrier: TanzaniaCarrier =
    TANZANIA_CARRIERS.find((c) => c.id === selectedCarrierId) || TANZANIA_CARRIERS[0];

  const handleCopy = (text: string, identifier: string) => {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedDomain(identifier);
      setTimeout(() => setCopiedDomain(null), 2000);
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

  const handleGenerateCustomPayload = () => {
    if (!customHost.trim()) return;
    const clean = customHost.trim().toLowerCase().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    const payload = `GET / HTTP/1.1[crlf]Host: ${clean}[crlf]X-Online-Host: ${clean}[crlf]X-Forward-Host: ${clean}[crlf]Connection: Upgrade[crlf]Upgrade: websocket[crlf][crlf]`;
    setGeneratedPayload(payload);
  };

  return (
    <div className="card-modern rounded-2xl p-4 sm:p-5 shadow-2xl border border-sky-500/30 mb-4 bg-slate-900/90 transition">
      {/* Header with Collapse Toggle */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-emerald-500 via-sky-500 to-indigo-600 flex items-center justify-center text-sm shadow-md shadow-sky-500/20">
            🇹🇿
          </div>
          <div>
            <h2 className="text-sm sm:text-base font-extrabold text-white flex items-center gap-2">
              <span>Tanzania Carrier &amp; Host Line Sync Hub</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/70 text-emerald-300 border border-emerald-700/50">
                Live Presets
              </span>
            </h2>
            <p className="text-[11px] text-slate-300">
              Synchronize, inspect, and verify host lines, SNI endpoints, and config files for Tanzanian carriers
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            type="button"
            onClick={() => setIsExpanded(!isExpanded)}
            className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 cursor-pointer transition flex items-center gap-1.5"
          >
            <span>{isExpanded ? 'Hide Hub' : 'Open Hub'}</span>
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

          {/* Host Lines Section */}
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
              {activeCarrier.hostLines.map((hl, idx) => (
                <div
                  key={idx}
                  className="bg-slate-950/80 border border-slate-800 hover:border-sky-500/40 rounded-xl p-3 transition space-y-2 flex flex-col justify-between"
                >
                  <div>
                    <div className="flex items-center justify-between gap-1 mb-1">
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-sky-950/60 text-sky-300 border border-sky-800/50">
                        {hl.category}
                      </span>
                      <span className="text-[10px] font-mono text-emerald-400 font-semibold">
                        Port {hl.recommendedPort} • {hl.tunnelMethod}
                      </span>
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
                      {copiedDomain === `hl-${idx}` ? 'Copied' : 'Copy'}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy(hl.samplePayload, `pl-${idx}`)}
                      className="py-1 px-2 rounded-lg bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-300 text-xs font-semibold border border-indigo-500/30 cursor-pointer transition"
                      title="Copy standard HTTP [crlf] payload"
                    >
                      {copiedDomain === `pl-${idx}` ? 'Copied Payload' : 'Payload'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Verified Configuration Templates Section */}
          <div className="space-y-2">
            <span className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-indigo-400"></span>
              Verified {activeCarrier.name} Profile Files ({activeCarrier.templates.length})
            </span>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {activeCarrier.templates.map((tpl, tIdx) => (
                <div
                  key={tIdx}
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
                    <span className="text-[10px] font-mono text-sky-400 block mt-1 font-semibold">
                      Protocol: {tpl.protocol}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 pt-2.5 mt-2 border-t border-slate-900">
                    <button
                      type="button"
                      onClick={() => handleApplyTemplate(tpl)}
                      className="flex-1 py-1.5 px-3 rounded-lg bg-gradient-to-r from-sky-600 to-indigo-600 hover:opacity-90 text-white text-xs font-bold cursor-pointer transition shadow-md shadow-sky-500/20 flex items-center justify-center gap-1.5"
                    >
                      <span>Load &amp; Verify Profile</span>
                      <svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2.5} d="M14 5l7 7m0 0l-7 7m7-7H3" />
                      </svg>
                    </button>
                    <button
                      type="button"
                      onClick={() => handleCopy(tpl.rawConfig, `tpl-${tIdx}`)}
                      className="py-1.5 px-2.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 cursor-pointer transition"
                    >
                      {copiedDomain === `tpl-${tIdx}` ? 'Copied' : 'Copy'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Custom Host Line to Payload Generator */}
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
                      {copiedDomain === 'customPl' ? 'Copied!' : 'Copy Payload'}
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
