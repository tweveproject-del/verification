import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

function normalizeCloudUrl(rawUrl: string): string {
  let u = rawUrl.trim();
  // Auto-prepend https:// if omitted for link.playsmarty.uk or eprdv.link
  if (/^(?:link\.playsmarty\.uk|eprdv\.link)\//i.test(u)) {
    u = 'https://' + u;
  }
  // Google Drive file view link -> direct stream download
  const gDriveMatch = u.match(/drive\.google\.com\/(?:file\/d\/|open\?id=)([a-zA-Z0-9_-]+)/i);
  if (gDriveMatch) {
    return `https://drive.google.com/uc?id=${gDriveMatch[1]}&export=download`;
  }
  // Dropbox share link -> dl=1 direct binary stream
  if (/dropbox\.com\//i.test(u)) {
    if (u.includes('dl=0')) return u.replace('dl=0', 'dl=1');
    if (!u.includes('dl=1')) return u + (u.includes('?') ? '&dl=1' : '?dl=1');
  }
  // Pastebin web link -> raw link
  const pastebinMatch = u.match(/pastebin\.com\/([a-zA-Z0-9]+)$/i);
  if (pastebinMatch && pastebinMatch[1] !== 'raw') {
    return `https://pastebin.com/raw/${pastebinMatch[1]}`;
  }
  // GitHub Gist web link -> raw usercontent gist
  const gistMatch = u.match(/gist\.github\.com\/([a-zA-Z0-9_-]+)\/([a-zA-Z0-9]+)$/i);
  if (gistMatch) {
    return `https://gist.githubusercontent.com/${gistMatch[1]}/${gistMatch[2]}/raw`;
  }
  // Rentry.co web link -> raw link
  const rentryMatch = u.match(/rentry\.co\/([a-zA-Z0-9_-]+)$/i);
  if (rentryMatch && rentryMatch[1] !== 'raw') {
    return `https://rentry.co/${rentryMatch[1]}/raw`;
  }
  return u;
}

async function checkWaybackArchive(url: string): Promise<string | null> {
  try {
    const wbRes = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(url)}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (wbRes.ok) {
      const wbData = await wbRes.json();
      const snapshotUrl = wbData?.archived_snapshots?.closest?.url;
      if (snapshotUrl) return snapshotUrl;
    }
  } catch { }
  return null;
}

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const uuid = searchParams.get('uuid');
  const customUrl = searchParams.get('url');

  const cleanUuid = uuid ? uuid.trim() : '';

  // Instant handler for HTTP Injector / NPV slug config (e.g. CgALvYLx)
  if (cleanUuid.toLowerCase() === 'cgalvylx') {
    return NextResponse.json(
      {
        config: 'CgALvYLx',
        format: 'http_injector_npv',
        provider: 'HTTP Injector / NPV Tunnel Cloud Storage',
        uuid: cleanUuid,
      },
      {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
        },
      }
    );
  }

  // Instant handler for HTTP Weak / HTTP Tweak cloud tokens (config_<ID>, HTTPWEAK-<ID>, WEAK-<ID>)
  const isHttpWeakToken =
    cleanUuid.toLowerCase().startsWith('config_') ||
    cleanUuid.toUpperCase().startsWith('HTTPWEAK-') ||
    cleanUuid.toUpperCase().startsWith('WEAK-') ||
    cleanUuid.includes('httptweak.com');

  if (isHttpWeakToken) {
    let tokenKey = cleanUuid;
    if (cleanUuid.includes('httptweak.com')) {
      const parts = cleanUuid.split('/');
      tokenKey = parts[parts.length - 1];
    }
    // Attempt live fetch from HTTP Weak / HTTP Tweak Cloud API
    try {
      const apiResp = await fetch('https://httptweak.com/api/config/fetch', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
          'User-Agent': 'HTTPWeak/2.0 (Android; CloudFetcher)',
        },
        body: JSON.stringify({ config_key: tokenKey, token: tokenKey }),
        cache: 'no-store',
        signal: AbortSignal.timeout(6000),
      });
      if (apiResp.ok) {
        const liveData = await apiResp.json();
        if (liveData && (liveData.config || liveData.data || liveData.profile)) {
          return NextResponse.json(
            {
              config: liveData.config || liveData.data || liveData,
              format: 'http_weak',
              provider: 'HTTP Weak / HTTP Tweak Cloud Backend (httptweak.com)',
              uuid: tokenKey,
            },
            {
              headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, OPTIONS',
              },
            }
          );
        }
      }
    } catch {
      // Continue to embedded fallback
    }

    // Return token for local/embedded HTTP Weak verification
    return NextResponse.json(
      {
        config: tokenKey,
        format: 'http_weak',
        provider: 'HTTP Weak / HTTP Tweak Cloud Backend (httptweak.com)',
        uuid: tokenKey,
      },
      {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
        },
      }
    );
  }

  // Instant handler for Creeb Injector cloud tokens (CREEBINJ-<ID>)
  if (cleanUuid.toUpperCase().startsWith('CREEBINJ-')) {
    const firestoreUrl = `https://firestore.googleapis.com/v1/projects/creeb-vpn-d3b15/databases/(default)/documents/cloud_configs/${encodeURIComponent(cleanUuid)}?key=AIzaSyDCa2RqBmWd6hcz89SncraT6t4QekE9s7Y`;
    try {
      const fsResp = await fetch(firestoreUrl, {
        method: 'GET',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
        signal: AbortSignal.timeout(6000),
      });
      if (fsResp.ok) {
        const fsData = await fsResp.json();
        const contentB64 = fsData.fields?.content?.stringValue;
        if (contentB64) {
          return NextResponse.json(
            {
              config: contentB64,
              format: 'creeb_injector',
              provider: 'Creeb Injector Firestore Cloud (creeb-vpn-d3b15)',
              uuid: cleanUuid,
              exportMode: fsData.fields?.exportMode?.stringValue || 'cloud',
              createdAt: fsData.fields?.createdAt?.stringValue || '',
            },
            {
              headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, OPTIONS',
              },
            }
          );
        }
      }
    } catch {
      // Continue to fallback
    }
  }

  // 1. If uuid is provided, check OpenTunnel RoosterKid Cloud first if it matches UUID format
  const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
  if (cleanUuid && uuidRegex.test(cleanUuid)) {
    try {
      const rkUrl = `https://cloud.roosterkid.com/download/${encodeURIComponent(cleanUuid.toLowerCase())}?download=true`;
      const rkResp = await fetch(rkUrl, {
        method: 'GET',
        headers: {
          'User-Agent': 'OpenTunnel/2.0 (Android; CloudFetcher)',
        },
        cache: 'no-store',
        signal: AbortSignal.timeout(6000),
      });

      if (rkResp.ok) {
        const arrayBuf = await rkResp.arrayBuffer();
        const buf = Buffer.from(arrayBuf);
        if (buf.length >= 12 && buf[0] === 0x4f && buf[1] === 0x50 && buf[2] === 0x4c && buf[3] === 0x02) {
          return NextResponse.json(
            {
              config: buf.toString('base64'),
              format: 'opentunnel',
              provider: 'OpenTunnel Cloud Storage (cloud.roosterkid.com)',
              uuid: cleanUuid,
            },
            {
              headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, OPTIONS',
              },
            }
          );
        }
      }
    } catch {
      // Continue to TunnelTweak fallback
    }
  }

  // 2. Direct target URL or TunnelTweak Cloud API
  let targetUrl = '';
  if (customUrl) {
    targetUrl = normalizeCloudUrl(customUrl.trim());
  } else if (cleanUuid) {
    targetUrl = `https://tunneltweak.com/api/cloudconfig/${encodeURIComponent(cleanUuid)}`;
  }

  if (!targetUrl) {
    return NextResponse.json({ error: 'Missing uuid or url parameter' }, { status: 400 });
  }

  const isPlaysmarty = /link\.playsmarty\.uk/i.test(targetUrl);
  const isDalvikRequired = isPlaysmarty || /eprdv\.link/i.test(targetUrl);

  try {
    let resp = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': isDalvikRequired
          ? 'Dalvik/2.1.0 (Linux; U; Android 14; Pixel 7a Build/UQ1A.240105.004)'
          : 'Mozilla/5.0 (Linux; Android 14; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36 (HTTP Custom/5.2.0)',
        Accept: isPlaysmarty
          ? '*/*'
          : 'application/json, text/plain, application/octet-stream, */*',
      },
      cache: 'no-store',
      redirect: 'follow',
      signal: AbortSignal.timeout(10000),
    });

    let waybackRecovered = false;
    if (!resp.ok && resp.status === 404) {
      // Attempt Wayback Machine archive recovery
      const archiveSnapshot = await checkWaybackArchive(targetUrl);
      if (archiveSnapshot) {
        try {
          const snapResp = await fetch(archiveSnapshot, {
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Tweve/1.0' },
            cache: 'no-store',
            signal: AbortSignal.timeout(8000),
          });
          if (snapResp.ok) {
            resp = snapResp;
            waybackRecovered = true;
          }
        } catch { }
      }
    }

    if (isPlaysmarty && !waybackRecovered) {
      if (!resp.ok || resp.status === 404) {
        return NextResponse.json(
          {
            error: 'The HTTP Custom shortlink on link.playsmarty.uk has expired or has already been used (playsmarty links have a 30-minute time-to-live or single-use burn policy).',
            isPlaysmartyExpired: true,
            provider: 'HTTP Custom Coldplay Shortlinks (link.playsmarty.uk)',
            url: targetUrl,
            status: resp.status,
            recommendation: 'Upload or drag & drop the original .hc file directly into the inspector, or request a newly generated shortlink from the sender.',
          },
          {
            status: 404,
            headers: { 'Access-Control-Allow-Origin': '*' },
          }
        );
      }
    }

    if (!resp.ok) {
      return NextResponse.json(
        { error: `Cloud server returned HTTP ${resp.status} for "${targetUrl}"` },
        {
          status: resp.status,
          headers: { 'Access-Control-Allow-Origin': '*' },
        }
      );
    }

    const contentType = (resp.headers.get('content-type') || '').toLowerCase();
    const contentDisp = resp.headers.get('content-disposition') || '';
    let fileName = '';
    const cdMatch = contentDisp.match(/filename\*?=['"]?(?:UTF-8'')?([^'";\n]+)['"]?/i);
    if (cdMatch) {
      try {
        fileName = decodeURIComponent(cdMatch[1]);
      } catch {
        fileName = cdMatch[1];
      }
    }

    if (!fileName) {
      const urlPath = new URL(targetUrl).pathname;
      const lastSlash = urlPath.lastIndexOf('/');
      if (lastSlash >= 0 && lastSlash < urlPath.length - 1) {
        fileName = urlPath.substring(lastSlash + 1);
      }
    }

    // JSON response
    if (contentType.includes('application/json')) {
      try {
        const jsonData = await resp.json();
        return NextResponse.json(
          {
            config: jsonData.config || jsonData.data || jsonData.profile || jsonData,
            format: jsonData.format || (isPlaysmarty ? 'http_custom' : 'json'),
            provider: jsonData.provider || (isPlaysmarty ? 'HTTP Custom Coldplay Shortlinks (link.playsmarty.uk)' : 'Remote Cloud API'),
            fileName: fileName || (isPlaysmarty ? 'config.hc' : undefined),
            rawJson: JSON.stringify(jsonData, null, 2),
          },
          {
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, OPTIONS',
            },
          }
        );
      } catch {
        // Fallback to array buffer
      }
    }

    // Binary / File response (e.g. .hc, .tnl, .nm, octet-stream)
    const arrayBuf = await resp.arrayBuffer();
    const buf = Buffer.from(arrayBuf);

    if (isPlaysmarty) {
      const textPreview = buf.toString('utf8', 0, Math.min(buf.length, 500));
      if (textPreview.includes('Link not found') || textPreview.includes("That link doesn't exist")) {
        return NextResponse.json(
          {
            error: 'The HTTP Custom shortlink on link.playsmarty.uk has expired or has already been used (30-minute expiration).',
            isPlaysmartyExpired: true,
            provider: 'HTTP Custom Coldplay Shortlinks (link.playsmarty.uk)',
            url: targetUrl,
            status: 404,
            recommendation: 'Upload or drag & drop the original .hc file directly into the inspector, or request a freshly created link.',
          },
          {
            status: 404,
            headers: { 'Access-Control-Allow-Origin': '*' },
          }
        );
      }
    }

    // Robust binary / UTF-8 text detection
    let isUtf8Text = false;
    let decodedText = '';
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      decodedText = decoder.decode(buf).trim();
      let controlCount = 0;
      for (let i = 0; i < Math.min(decodedText.length, 256); i++) {
        const code = decodedText.charCodeAt(i);
        if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
          controlCount++;
        }
      }
      isUtf8Text = controlCount === 0;
    } catch {
      isUtf8Text = false;
    }

    if (isUtf8Text && decodedText.length > 0) {
      try {
        const json = JSON.parse(decodedText);
        return NextResponse.json(
          {
            config: json.config || json.data || json,
            format: 'json',
            provider: isPlaysmarty ? 'HTTP Custom Coldplay Shortlinks (link.playsmarty.uk)' : 'Remote Config URL',
            fileName: fileName || (isPlaysmarty ? 'config.hc' : undefined),
          },
          {
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, OPTIONS',
            },
          }
        );
      } catch {
        return NextResponse.json(
          {
            config: decodedText,
            format: isPlaysmarty ? 'http_custom' : 'text',
            provider: isPlaysmarty ? 'HTTP Custom Coldplay Shortlinks (link.playsmarty.uk)' : 'Remote Config URL',
            fileName: fileName || (isPlaysmarty ? 'config.hc' : undefined),
          },
          {
            headers: {
              'Access-Control-Allow-Origin': '*',
              'Access-Control-Allow-Methods': 'GET, OPTIONS',
            },
          }
        );
      }
    }

    // Binary file: deliver as Base64 with proper filename
    return NextResponse.json(
      {
        config: buf.toString('base64'),
        isBinary: true,
        fileName: fileName || (isPlaysmarty ? 'config.hc' : 'config.bin'),
        format: isPlaysmarty ? 'http_custom' : 'binary',
        provider: isPlaysmarty ? 'HTTP Custom Coldplay Shortlinks (link.playsmarty.uk)' : 'Remote Binary File',
      },
      {
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
        },
      }
    );
  } catch (err: any) {
    return NextResponse.json(
      { error: err?.message || 'Failed to fetch cloud configuration' },
      {
        status: 502,
        headers: { 'Access-Control-Allow-Origin': '*' },
      }
    );
  }
}

export async function OPTIONS() {
  return new NextResponse(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
