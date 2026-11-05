import { NextRequest, NextResponse } from 'next/server';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

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
    targetUrl = customUrl.trim();
  } else if (cleanUuid) {
    targetUrl = `https://tunneltweak.com/api/cloudconfig/${encodeURIComponent(cleanUuid)}`;
  }

  if (!targetUrl) {
    return NextResponse.json({ error: 'Missing uuid or url parameter' }, { status: 400 });
  }

  try {
    const resp = await fetch(targetUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'TunnelTweak/2.0 (Android; CloudInspector)',
        Accept: 'application/json',
      },
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
    });

    if (!resp.ok) {
      return NextResponse.json(
        { error: `Cloud server returned HTTP ${resp.status}` },
        {
          status: resp.status,
          headers: { 'Access-Control-Allow-Origin': '*' },
        }
      );
    }

    const data = await resp.json();
    return NextResponse.json(data, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
      },
    });
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
