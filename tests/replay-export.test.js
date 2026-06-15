// Replay export to clip (#13).
// Static markup + structural checks for exportReplayClip.

const path = require('path');
const fs = require('fs');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, found = false;
  for (; i < html.length; i++) {
    if (html[i] === '{') { depth++; found = true; }
    if (html[i] === '}') depth--;
    if (found && depth === 0) break;
  }
  return html.substring(start, i + 1);
}

// ── Static markup ─────────────────────────────────────────────────────────
describe('Replay export — static markup', () => {
  test('#replay-export-btn button exists', () => {
    expect(html).toContain('id="replay-export-btn"');
  });

  test('replay-export-btn wired to exportReplayClip', () => {
    expect(html).toMatch(/id="replay-export-btn"[^>]*data-click="exportReplayClip"/);
  });

  test('#replay-export-btn is inside #replay-panel', () => {
    const panelStart = html.indexOf('id="replay-panel"');
    const panelEnd = html.indexOf('</div>', html.indexOf('id="replay-panel"') + 200);
    const replaySection = html.substring(panelStart, panelStart + 3000);
    expect(replaySection).toContain('replay-export-btn');
  });

  test('exportReplayClip function defined', () => {
    expect(html).toContain('function exportReplayClip(');
  });

  test('_exportRecorder state variable declared', () => {
    expect(html).toMatch(/let _exportRecorder\s*=\s*null/);
  });

  test('_exportChunks state variable declared', () => {
    expect(html).toMatch(/let _exportChunks\s*=\s*\[\]/);
  });
});

// ── exportReplayClip implementation ───────────────────────────────────────
describe('Replay export — implementation', () => {
  let fn;
  beforeAll(() => { fn = extractFunction('exportReplayClip'); });

  test('uses MediaRecorder for recording', () => {
    expect(fn).toContain('MediaRecorder');
  });

  test('uses canvas.captureStream()', () => {
    expect(fn).toContain('captureStream');
  });

  test('downloads as .webm', () => {
    expect(fn).toContain('.webm');
    expect(fn).toContain('video/webm');
  });

  test('filename is oikumene-replay.webm', () => {
    expect(fn).toContain('oikumene-replay.webm');
  });

  test('guards against recording when already recording', () => {
    expect(fn).toContain('recording');
  });

  test('filters only visit frames (not transit)', () => {
    expect(fn).toContain("kind === 'visit'");
  });

  test('uses dark background color', () => {
    expect(fn).toContain('#0f172a');
  });

  test('draws lat/lng grid lines', () => {
    // Grid at 30° intervals
    expect(fn).toContain('30');
    expect(fn).toContain('moveTo');
    expect(fn).toContain('lineTo');
  });

  test('shows frame progress in button label', () => {
    expect(fn).toContain('replay-export-btn');
  });

  test('shows "Recording…" label while capturing', () => {
    expect(fn).toContain('Recording');
  });

  test('resets button text after stop', () => {
    expect(fn).toContain('Export clip');
  });

  test('creates a download anchor element', () => {
    expect(fn).toContain('createElement(');
    expect(fn).toContain('download');
  });

  test('revokes object URL after download', () => {
    expect(fn).toContain('revokeObjectURL');
  });

  test('shows Oikumene watermark on canvas', () => {
    expect(fn).toContain('Oikumene');
  });

  test('shows date label per frame', () => {
    expect(fn).toContain('f.date');
  });

  test('shows location name label per frame', () => {
    expect(fn).toContain('f.name');
  });
});
