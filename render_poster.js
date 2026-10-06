const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

async function renderPoster() {
  const chromePath = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
  const tempDir = path.join(__dirname, '.chrome_poster_render');
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

  const htmlPath = path.resolve(__dirname, 'poster_a3.html');
  const fileUrl = 'file:///' + htmlPath.replace(/\\/g, '/');
  console.log('Target file URL:', fileUrl);

  const port = 9555;
  const chrome = spawn(chromePath, [
    '--headless=new',
    `--remote-debugging-port=${port}`,
    `--user-data-dir=${tempDir}`,
    '--disable-gpu',
    '--no-sandbox',
    '--window-size=3508,2480',
    '--hide-scrollbars',
    '--force-device-scale-factor=1',
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
    console.log('Page attached:', newPage.webSocketDebuggerUrl);

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
    await send('Emulation.setDeviceMetricsOverride', {
      width: 3508,
      height: 2480,
      deviceScaleFactor: 1,
      mobile: false,
      fitWindow: false
    });

    console.log('Waiting for poster layout and fonts to render...');
    await new Promise(r => setTimeout(r, 2500));

    // Capture PNG
    console.log('Capturing PNG...');
    const pngResult = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false, fromSurface: true });
    const pngBuf = Buffer.from(pngResult.data, 'base64');
    const pngOut = path.join(__dirname, 'poster_a3_rendered.png');
    fs.writeFileSync(pngOut, pngBuf);

    // Capture JPEG
    console.log('Capturing JPEG...');
    const jpgResult = await send('Page.captureScreenshot', { format: 'jpeg', quality: 100, captureBeyondViewport: false, fromSurface: true });
    const jpgBuf = Buffer.from(jpgResult.data, 'base64');
    const jpgOut = path.join(__dirname, 'poster_a3_rendered.jpg');
    fs.writeFileSync(jpgOut, jpgBuf);

    // Print to Vector PDF (A3 landscape)
    console.log('Printing to Vector PDF (A3 landscape, 420mm x 297mm)...');
    const pdfResult = await send('Page.printToPDF', {
      landscape: true,
      displayHeaderFooter: false,
      printBackground: true,
      paperWidth: 16.5354, // 420mm
      paperHeight: 11.6929, // 297mm
      marginTop: 0,
      marginBottom: 0,
      marginLeft: 0,
      marginRight: 0,
      preferCSSPageSize: true
    });
    const pdfBuf = Buffer.from(pdfResult.data, 'base64');
    const pdfOut = path.join(__dirname, 'poster_a3_rendered.pdf');
    fs.writeFileSync(pdfOut, pdfBuf);
    console.log(`Saved PDF: ${pdfOut} (${(pdfBuf.length / 1024 / 1024).toFixed(2)} MB)`);

    // Copy to artifact directory
    const artifactDir = 'C:\\Users\\vvsri\\.gemini\antigravity-ide\\brain\\ee93d25b-9ceb-454a-a722-a3f47a26c894';
    if (fs.existsSync(artifactDir)) {
      fs.copyFileSync(pngOut, path.join(artifactDir, 'poster_a3_rendered.png'));
      fs.copyFileSync(jpgOut, path.join(artifactDir, 'poster_a3_rendered.jpg'));
      fs.copyFileSync(pdfOut, path.join(artifactDir, 'poster_a3_rendered.pdf'));
      console.log('Copied all rendered poster formats to artifact directory!');
    }

    ws.close();
    console.log('All render steps completed successfully!');
  } finally {
    try { chrome.kill('SIGKILL'); } catch (e) {}
  }
}

renderPoster().catch(err => {
  console.error('Render failed:', err);
  process.exit(1);
});
