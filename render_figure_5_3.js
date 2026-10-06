const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

async function renderScreenshot(htmlFileName, outputBaseName, width = 1560, height = 1400) {
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const tempDir = path.join(__dirname, '.chrome_render_5_3');
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  const htmlPath = path.resolve(__dirname, htmlFileName);
  const fileUrl = 'file:///' + htmlPath.replace(/\\/g, '/');
  console.log(`\n========================================`);
  console.log(`Rendering ${htmlFileName} -> ${outputBaseName}...`);

  const port = 9888;
  const chrome = spawn(chromePath, [
    '--headless=new',
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${tempDir}`,
    '--disable-gpu',
    '--no-sandbox',
    `--window-size=${width},${height}`,
    '--hide-scrollbars',
    '--force-device-scale-factor=2',
    'about:blank'
  ]);

  try {
    let newPage = null;
    for (let i = 0; i < 40; i++) {
      await new Promise(r => setTimeout(r, 200));
      try {
        const res = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(fileUrl)}`, { method: 'PUT' });
        newPage = await res.json();
        if (newPage && newPage.webSocketDebuggerUrl) break;
      } catch (e) {}
    }

    if (!newPage) throw new Error('Could not spawn Chrome page session');

    const ws = new WebSocket(newPage.webSocketDebuggerUrl);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = reject;
    });

    let msgId = 1;
    function send(method, params = {}) {
      return new Promise((resolve, reject) => {
        const id = msgId++;
        const handler = (evt) => {
          const res = JSON.parse(evt.data);
          if (res.id === id) {
            ws.removeEventListener('message', handler);
            if (res.error) reject(new Error(JSON.stringify(res.error)));
            else resolve(res.result);
          }
        };
        ws.addEventListener('message', handler);
        ws.send(JSON.stringify({ id, method, params }));
      });
    }

    await send('Page.enable');
    await send('Runtime.enable');

    // Wait for fonts & DOM
    await new Promise(r => setTimeout(r, 2000));

    // Get measured height of content
    const evalRes = await send('Runtime.evaluate', {
      expression: `(() => {
        const el = document.querySelector('.ide-window') || document.body;
        const rect = el.getBoundingClientRect();
        return { width: Math.ceil(rect.width), height: Math.ceil(rect.height) };
      })()`,
      returnByValue: true
    });
    const measured = evalRes.result.value || { width, height };
    console.log('Measured content dimensions:', measured);

    const targetWidth = Math.max(width, measured.width + 70);
    const targetHeight = measured.height + 70;

    await send('Emulation.setDeviceMetricsOverride', {
      width: targetWidth,
      height: targetHeight,
      deviceScaleFactor: 2,
      mobile: false,
      fitWindow: false
    });

    await new Promise(r => setTimeout(r, 1200));

    const screenshotsDir = path.join(__dirname, 'screenshots');
    if (!fs.existsSync(screenshotsDir)) fs.mkdirSync(screenshotsDir, { recursive: true });

    // Capture PNG
    const pngResult = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false, fromSurface: true });
    const pngBuf = Buffer.from(pngResult.data, 'base64');
    const pngOut = path.join(screenshotsDir, `${outputBaseName}.png`);
    fs.writeFileSync(pngOut, pngBuf);
    console.log(`[SUCCESS] Saved PNG: ${pngOut} (${(pngBuf.length / 1024).toFixed(1)} KB)`);

    // Capture JPEG
    const jpgResult = await send('Page.captureScreenshot', { format: 'jpeg', quality: 96, captureBeyondViewport: false, fromSurface: true });
    const jpgBuf = Buffer.from(jpgResult.data, 'base64');
    const jpgOut = path.join(screenshotsDir, `${outputBaseName}.jpg`);
    fs.writeFileSync(jpgOut, jpgBuf);
    console.log(`[SUCCESS] Saved JPG: ${jpgOut} (${(jpgBuf.length / 1024).toFixed(1)} KB)`);

    // Copy to artifact directory
    const artifactDir = 'C:\\Users\\vvsri\\.gemini\\antigravity-ide\\brain\\72ec9147-8c5e-4a0d-a844-33f4c84ca543';
    if (fs.existsSync(artifactDir)) {
      fs.copyFileSync(pngOut, path.join(artifactDir, `${outputBaseName}.png`));
      fs.copyFileSync(jpgOut, path.join(artifactDir, `${outputBaseName}.jpg`));
      console.log(`[COPIED] Copied to artifact dir: ${outputBaseName}`);
    }

    ws.close();
  } finally {
    try { chrome.kill('SIGKILL'); } catch (e) {}
  }
}

async function main() {
  await renderScreenshot('markdown_report_view.html', 'figure_5_3_generated_markdown_incident_report', 1540, 1600);
  console.log('\nFigure 5.3 rendered successfully!');
}

main().catch(err => {
  console.error('Render error:', err);
  process.exit(1);
});
