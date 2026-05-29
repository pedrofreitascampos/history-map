// Wipes the e2e data dir so each test run starts from a clean DB.
// Invoked from the test:e2e npm script BEFORE Playwright starts the webServer
// (NeDB autoloads on open, so we can't touch files while the server is up).

const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '..', 'data-e2e');
if (fs.existsSync(dir)) {
  for (const f of fs.readdirSync(dir)) {
    fs.rmSync(path.join(dir, f), { recursive: true, force: true });
  }
} else {
  fs.mkdirSync(dir, { recursive: true });
}

const authDir = path.join(__dirname, '.auth');
if (fs.existsSync(authDir)) {
  fs.rmSync(authDir, { recursive: true, force: true });
}
fs.mkdirSync(authDir, { recursive: true });
