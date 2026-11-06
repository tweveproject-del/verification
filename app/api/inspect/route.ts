import { NextResponse } from 'next/server';
import { inspectConfigLocally } from '@/app/inspector-engine';

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const result = await inspectConfigLocally({
      input: body.input,
      fileName: body.fileName,
      passphrase: body.passphrase,
      runNetworkProbes: body.runNetworkProbes,
      manualServerHost: body.manualServerHost,
      manualServerPort: body.manualServerPort,
      manualSni: body.manualSni,
      manualNameserver: body.manualNameserver,
      customCloudUrl: body.customCloudUrl,
    });
    return NextResponse.json(result);
  } catch (err: any) {
    return NextResponse.json(
      { error: `Inspector error: ${err?.message || 'Unknown error'}` },
      { status: 500 }
    );
  }
}
