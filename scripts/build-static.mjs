import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

const apiDir = path.join(projectRoot, 'app', 'api');
const tempApiDir = path.join(projectRoot, 'temp_api_backup');
const publicDir = path.join(projectRoot, 'public');
const outDir = path.join(projectRoot, 'out');

console.log('--- Starting Tweve Tunnel Static Build ---');

let movedApi = false;
try {
  if (fs.existsSync(apiDir)) {
    console.log('[1/4] Temporarily parking app/api for static export...');
    fs.renameSync(apiDir, tempApiDir);
    movedApi = true;
  }

  console.log('[2/4] Running next build (output: export)...');
  execSync('npx next build', {
    cwd: projectRoot,
    stdio: 'inherit',
    env: { ...process.env, NODE_ENV: 'production' },
  });
} finally {
  if (movedApi && fs.existsSync(tempApiDir)) {
    console.log('[3/4] Restoring app/api for dev server & local inspection...');
    if (fs.existsSync(apiDir)) {
      fs.rmSync(apiDir, { recursive: true, force: true });
    }
    fs.renameSync(tempApiDir, apiDir);
  }
}

console.log('[4/4] Syncing safe downloadable assets (ZIP and DAT) to out/ ...');
if (fs.existsSync(outDir) && fs.existsSync(publicDir)) {
  const assetsToSync = [
    'twevetunnel.dat',
    'TweveTunnel.zip',
    'twevetunnel.zip',
  ];

  for (const asset of assetsToSync) {
    const src = path.join(publicDir, asset);
    const dest = path.join(outDir, asset);
    if (fs.existsSync(src)) {
      fs.copyFileSync(src, dest);
      console.log(`  ✓ Synced ${asset} (${(fs.statSync(src).size / 1024 / 1024).toFixed(1)} MB) to out/`);
    }
  }

  // Ensure no forbidden .apk files remain in out/ that cause Firebase Hosting Spark plan 400 errors
  const outFiles = fs.readdirSync(outDir);
  for (const f of outFiles) {
    if (f.endsWith('.apk')) {
      fs.unlinkSync(path.join(outDir, f));
      console.log(`  Removed ${f} from out/ (Firebase Spark plan forbids .apk files on hosting)`);
    }
  }
}

console.log('--- Static Build & Asset Sync Completed Successfully! ---');
