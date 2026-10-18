import path from 'path';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const backendDir = 'c:\\Users\\srisn\\Desktop\\Projects\\sentinelai-complete\\backend';
const puppeteer = require(path.join(backendDir, 'node_modules', 'puppeteer-core'));

async function run() {
  const browser = await puppeteer.launch({
    executablePath: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    headless: 'new',
  });
  const page = await browser.newPage();
  const notFoundList = [];

  page.on('response', (r) => {
    if (r.status() === 404) {
      const info = {
        method: r.request().method(),
        url: r.url(),
        resourceType: r.request().resourceType(),
        status: r.status(),
      };
      notFoundList.push(info);
      console.log('404 DETECTED:', JSON.stringify(info));
    }
  });

  await page.goto('http://localhost:3000/login', { waitUntil: 'domcontentloaded' });
  await page.evaluate(() => { localStorage.clear(); sessionStorage.clear(); });
  await page.goto('http://localhost:3000/login', { waitUntil: 'domcontentloaded' });

  const email = await page.waitForSelector('input[type="email"]');
  await email.type('sara@sentinel.io');
  const viewerPassword = process.env.VERIFY_VIEWER_PASSWORD;
  if (!viewerPassword) throw new Error('VERIFY_VIEWER_PASSWORD env var is required');
  await pass.type(viewerPassword);

  await page.evaluate(() => {
    const btns = Array.from(document.querySelectorAll('button'));
    const b = btns.find((x) => x.innerText.includes('AUTHENTICATE'));
    if (b) b.click();
  });

  await page.waitForFunction(() => window.location.pathname === '/dashboard', { timeout: 10000 });
  await new Promise((r) => setTimeout(r, 2000));

  console.log('\n--- Full Summary of 404s During Login ---');
  console.log(JSON.stringify(notFoundList, null, 2));

  await browser.close();
}

run().catch(console.error);
