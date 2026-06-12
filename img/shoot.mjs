// Screenshot capture of the find_evil app dashboards (Splunk Web).
import { chromium } from "playwright";

const USER = process.env.SPLUNK_USERNAME || "julien";
const PASS = process.env.SPLUNK_PASSWORD;
const BASE = "http://localhost:8000/en-US";
const OUT = process.cwd();

const VIEWS = [
  { name: "01_app_launcher", url: `${BASE}/app/launcher/home`, wait: 4000 },
  { name: "02_a2ui_native", url: `${BASE}/app/find_evil/a2ui_native`, wait: 7000 },
  { name: "03_soc_incidents", url: `${BASE}/app/find_evil/soc_incidents`, wait: 9000 },
  { name: "04_ai_investigation", url: `${BASE}/app/find_evil/ai_investigation`, wait: 38000 },
  { name: "05_command_center", url: `${BASE}/app/find_evil/forensic_command_center`, wait: 12000 },
];

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const browser = await chromium.launch({ channel: "chrome", headless: true });
const ctx = await browser.newContext({ viewport: { width: 1600, height: 1000 }, ignoreHTTPSErrors: true });
const page = await ctx.newPage();

// --- Login Splunk ---
await page.goto(`${BASE}/account/login`, { waitUntil: "domcontentloaded" });
await page.fill('input[name="username"]', USER);
await page.fill('input[name="password"]', PASS);
await Promise.all([
  page.waitForLoadState("networkidle").catch(() => {}),
  page.click('input[type="submit"], button[type="submit"]'),
]);
await sleep(3000);
console.log("Connected to Splunk.");

// --- Captures ---
for (const v of VIEWS) {
  try {
    await page.goto(v.url, { waitUntil: "domcontentloaded" });
    await sleep(v.wait); // let the searches / | ai / React A2UI render
    const file = `${OUT}/${v.name}.png`;
    await page.screenshot({ path: file, fullPage: true });
    console.log(`OK  ${v.name}.png`);
  } catch (e) {
    console.log(`ERR ${v.name}: ${e.message}`);
  }
}

await browser.close();
console.log("Done.");
