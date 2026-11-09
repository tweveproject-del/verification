import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const rawCode = searchParams.get('code') || searchParams.get('url') || '';
  
  if (!rawCode.trim()) {
    return NextResponse.json({ error: 'Missing code or url parameter' }, { status: 400 });
  }

  // Extract clean 5-10 character alphanumeric code from URL or raw input
  let code = rawCode.trim();
  const urlMatch = code.match(/link\.playsmarty\.uk\/([a-zA-Z0-9_-]+)/i);
  if (urlMatch) {
    code = urlMatch[1];
  } else {
    code = code.replace(/[^a-zA-Z0-9_-]/g, '');
  }

  if (!code) {
    return NextResponse.json({ error: 'Invalid playsmarty shortcode' }, { status: 400 });
  }

  const endpoint = `https://link.playsmarty.uk/api/stats/${encodeURIComponent(code)}`;
  const fullUrl = `https://link.playsmarty.uk/${code}`;

  try {
    const statsResp = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) TweveInspector/2.0',
      },
      cache: 'no-store',
      signal: AbortSignal.timeout(6000),
    });

    if (statsResp.ok) {
      const statsData = await statsResp.json().catch(() => ({}));
      return NextResponse.json({
        code,
        fullUrl,
        active: Boolean(statsData.active),
        status: statsData.active ? 'active' : 'unknown',
        message: statsData.active
          ? 'Live & Active — Waiting to be opened (Can be captured & verified now)'
          : 'Status unclear',
        checkedAt: new Date().toISOString(),
        burnPolicy: 'Single-use download or 30-minute automatic expiration',
      });
    }

    if (statsResp.status === 404) {
      return NextResponse.json({
        code,
        fullUrl,
        active: false,
        status: 'burned_or_expired',
        message: 'Opened or Expired — The file was downloaded once by HTTP Custom or the 30-minute TTL expired.',
        checkedAt: new Date().toISOString(),
        burnPolicy: 'Single-use download or 30-minute automatic expiration',
      });
    }

    return NextResponse.json({
      code,
      fullUrl,
      active: false,
      status: 'http_error',
      httpStatus: statsResp.status,
      message: `Playsmarty responded with HTTP ${statsResp.status}`,
      checkedAt: new Date().toISOString(),
    }, { status: statsResp.status });
  } catch (err: any) {
    return NextResponse.json({
      code,
      fullUrl,
      active: false,
      status: 'network_error',
      error: err?.message || 'Failed to reach link.playsmarty.uk',
      checkedAt: new Date().toISOString(),
    }, { status: 502 });
  }
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json();
    const { url, rawBase64, filename, alias } = body;

    // Mode 1: Binary .hc file upload
    if (rawBase64) {
      const buffer = Buffer.from(rawBase64, 'base64');
      const uploadResp = await fetch('https://link.playsmarty.uk/api/upload', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/octet-stream',
          'X-Filename': encodeURIComponent(filename || 'tweve_config.hc'),
          'X-Alias': alias ? encodeURIComponent(alias) : '',
        },
        body: buffer,
      });

      const data = await uploadResp.json().catch(() => ({}));
      if (!uploadResp.ok) {
        return NextResponse.json({ error: data.error || 'Failed to upload config to link.playsmarty.uk' }, { status: uploadResp.status });
      }

      return NextResponse.json({
        success: true,
        code: data.code,
        shortUrl: data.short || `https://link.playsmarty.uk/${data.code}`,
        expiresAt: data.expiresAt || (Date.now() + 30 * 60 * 1000),
        fileName: data.file || filename || 'config.hc',
        burnPolicy: 'One-time download or 30-minute expiration',
      });
    }

    // Mode 2: URL Shorten
    if (url) {
      const shortenResp = await fetch('https://link.playsmarty.uk/api/shorten', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url.trim(),
          alias: alias ? alias.trim() : undefined,
        }),
      });

      const data = await shortenResp.json().catch(() => ({}));
      if (!shortenResp.ok) {
        return NextResponse.json({ error: data.error || 'Failed to shorten URL on link.playsmarty.uk' }, { status: shortenResp.status });
      }

      return NextResponse.json({
        success: true,
        code: data.code,
        shortUrl: data.short || `https://link.playsmarty.uk/${data.code}`,
        expiresAt: data.expiresAt || (Date.now() + 30 * 60 * 1000),
        burnPolicy: 'One-time download or 30-minute expiration',
      });
    }

    return NextResponse.json({ error: 'Please provide either rawBase64 (for .hc config) or url' }, { status: 400 });
  } catch (err: any) {
    return NextResponse.json({ error: err?.message || 'Internal proxy error' }, { status: 500 });
  }
}
