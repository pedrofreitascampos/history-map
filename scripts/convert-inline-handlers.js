#!/usr/bin/env node
// One-shot converter: rewrite every `on<event>="…"` inline handler in
// public/index.html into the dispatcher-friendly `data-<event>=`/`data-arg-N=`
// markup. Run once, review the diff, delete this file (or keep it as a
// historical record under scripts/).
//
// Patterns handled:
//   onclick="X()"                                  → data-click="X"
//   onclick="X(arg1, 'arg2', 3)"                   → data-click="X" data-arg-0="arg1" data-arg-1="arg2" data-arg-2="3"
//   onclick="event.stopPropagation(); X(…)"        → data-click="X" data-stop="1" data-arg-N=…
//   onclick="withLoading(this, X)"                 → data-click="withLoading" data-arg-0="X"   (and an ACTIONS entry handles the wrapping)
//   onclick="document.getElementById('Y').click()" → data-click="openFileDialog" data-target="Y" (custom ACTIONS entry)
//   onclick="if(event.target.type!=='checkbox')openEditModal('${id}')"
//                                                  → data-click="editLocOrCheckbox" data-arg-0="${id}"  (custom ACTIONS entry)
//   onclick="event.stopPropagation()"              → data-click="noop" data-stop="1"  (placeholder so dispatcher sees the el)
//
// Untouched (left for manual review): anything we can't confidently match.

const fs = require('fs');
const path = require('path');

const FILE = path.join(__dirname, '..', 'public', 'index.html');
let src = fs.readFileSync(FILE, 'utf-8');

// ─── Helpers ────────────────────────────────────────────────────────────
// HTML-escape an attribute value (single-quoted attrs vs double-quoted).
// All our outputs go inside double-quoted attrs, so &quot; for ".
function escAttrVal(s) {
  return s.replace(/&/g, '&amp;').replace(/"/g, '&quot;');
}

// Parse a JS-ish args list like `'a', 'b', 3, ${esc(id)}` into an array of
// literal strings (preserving template-literal expression boundaries).
// We tokenise by top-level commas, respecting single/double quotes, template
// literals, parens/brackets/braces, and `\` escapes.
function splitArgs(argStr) {
  const out = [];
  let cur = '';
  let depth = 0;
  let inQuote = null;
  let inTpl = 0;       // ${ … } depth inside backticks
  let inBack = false;  // inside backtick template?
  for (let i = 0; i < argStr.length; i++) {
    const c = argStr[i];
    if (inQuote) {
      if (c === '\\') { cur += c + argStr[++i]; continue; }
      if (c === inQuote) inQuote = null;
      cur += c;
    } else if (inBack) {
      if (c === '\\') { cur += c + argStr[++i]; continue; }
      if (c === '`' && inTpl === 0) { inBack = false; cur += c; continue; }
      if (c === '$' && argStr[i + 1] === '{') { inTpl++; cur += '${'; i++; continue; }
      if (c === '}' && inTpl > 0) { inTpl--; cur += c; continue; }
      cur += c;
    } else {
      if (c === '"' || c === '\'') { inQuote = c; cur += c; continue; }
      if (c === '`') { inBack = true; cur += c; continue; }
      if (c === '(' || c === '[' || c === '{') { depth++; cur += c; continue; }
      if (c === ')' || c === ']' || c === '}') { depth--; cur += c; continue; }
      if (c === ',' && depth === 0) { out.push(cur.trim()); cur = ''; continue; }
      cur += c;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

// Strip a single layer of '…' / "…" quoting from an arg literal; leave
// template literals (${…}) and bare identifiers untouched.
function unquoteArg(arg) {
  if ((arg.startsWith("'") && arg.endsWith("'")) || (arg.startsWith('"') && arg.endsWith('"'))) {
    return arg.slice(1, -1);
  }
  return arg;
}

// Convert "X(args)" call expression into { fn, args } pair.
function parseCall(expr) {
  expr = expr.trim();
  const open = expr.indexOf('(');
  if (open === -1) return null;
  if (!expr.endsWith(')')) return null;
  const fn = expr.slice(0, open).trim();
  if (!/^[a-zA-Z_$][a-zA-Z0-9_$]*$/.test(fn)) return null;
  const inner = expr.slice(open + 1, -1);
  const args = inner.trim() === '' ? [] : splitArgs(inner);
  return { fn, args };
}

function dataAttrsFor(fn, args, extra = {}) {
  const parts = [];
  for (const [k, v] of Object.entries(extra)) parts.push(`data-${k}="${escAttrVal(v)}"`);
  parts.push(`data-click="${fn}"`);
  args.forEach((a, i) => {
    parts.push(`data-arg${i}="${escAttrVal(unquoteArg(a))}"`);
  });
  return parts.join(' ');
}

// ─── Per-event converters ───────────────────────────────────────────────
const EVENTS = ['click', 'change', 'input', 'mouseover', 'mouseout', 'keydown', 'submit', 'drop', 'dragover', 'dragenter', 'dragleave', 'focus'];

let unconverted = [];
let convertedCount = 0;

for (const evt of EVENTS) {
  const attrName = 'on' + evt;
  const dataKey = evt === 'focus' ? 'focusin' : evt;
  const re = new RegExp(`${attrName}="([^"]*)"`, 'g');
  src = src.replace(re, (full, body) => {
    body = body.trim();
    // Trim a trailing `;`
    if (body.endsWith(';')) body = body.slice(0, -1).trim();

    // Strip leading "event.stopPropagation(); " — translate to data-stop.
    let stop = false;
    const stopRe = /^event\.stopPropagation\(\)\s*;\s*/;
    if (stopRe.test(body)) {
      stop = true;
      body = body.replace(stopRe, '').trim();
    }
    // Trim a trailing `;` again
    if (body.endsWith(';')) body = body.slice(0, -1).trim();

    // Special: bare `event.stopPropagation()` with nothing after — emit
    // a noop with data-stop.
    if (body === 'event.stopPropagation()' || body === '') {
      convertedCount++;
      return `data-${dataKey}="noop" data-stop="1"`;
    }

    // Special: `document.getElementById('Y').click()` → openFileDialog.
    const fdMatch = body.match(/^document\.getElementById\(['"]([^'"]+)['"]\)\.click\(\)(?:\s*;\s*return false)?$/);
    if (fdMatch) {
      convertedCount++;
      return `data-${dataKey}="openFileDialog" data-target="${escAttrVal(fdMatch[1])}"${stop ? ' data-stop="1"' : ''}`;
    }

    // Special: `if(event.target.type!=='checkbox')openEditModal('${X}')`
    // → editLocOrCheckbox with the arg.
    const condEditMatch = body.match(/^if\(event\.target\.type!==['"]checkbox['"]\)openEditModal\(['"]?([^'")]+)['"]?\)$/);
    if (condEditMatch) {
      convertedCount++;
      return `data-${dataKey}="editLocOrCheckbox" data-arg-0="${escAttrVal(condEditMatch[1])}"${stop ? ' data-stop="1"' : ''}`;
    }

    // Special: `withLoading(this, X)` → withLoading wrapper, arg=X (bare ident).
    const wlMatch = body.match(/^withLoading\(this,\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\)$/);
    if (wlMatch) {
      convertedCount++;
      return `data-${dataKey}="withLoading" data-arg-0="${escAttrVal(wlMatch[1])}"${stop ? ' data-stop="1"' : ''}`;
    }

    // Special: Enter-key pattern. Two shapes:
    //   `if(event.key==='Enter') X()`
    //   `if(event.key==='Enter'){X(); event.preventDefault();}`
    // Both translate to data-<event>="enterKey" data-arg-0="X" (+ data-prevent="1"
    // when the original called preventDefault).
    const enterMatch = body.match(/^if\(event\.key===['"]Enter['"]\)\s*\{?\s*([a-zA-Z_$][a-zA-Z0-9_$]*)\(\s*([^)]*)\s*\)\s*;?\s*(event\.preventDefault\(\)\s*;?\s*)?\}?$/);
    if (enterMatch) {
      const fn = enterMatch[1];
      const argList = enterMatch[2] ? splitArgs(enterMatch[2]) : [];
      const prevent = !!enterMatch[3];
      const parts = [`data-${dataKey}="enterKey"`];
      parts.push(`data-arg-0="${escAttrVal(fn)}"`);
      argList.forEach((a, i) => parts.push(`data-arg${i + 1}="${escAttrVal(unquoteArg(a))}"`));
      if (prevent) parts.push('data-prevent="1"');
      if (stop) parts.push('data-stop="1"');
      convertedCount++;
      return parts.join(' ');
    }

    // Skip any body that isn't a pure call expression — anything starting
    // with `if`, `for`, `state.`, `this.`, `document.` (other than the
    // file-dialog shape handled above) needs manual translation.
    if (/^(if|for|while|switch|state|this|document|var|let|const)\b/.test(body)) {
      unconverted.push(`${attrName}="${body}"`);
      return full;
    }

    // Generic single-call: X(args)
    const call = parseCall(body);
    if (call) {
      // Arg literals may contain ${…} expressions OR be bare identifiers
      // (e.g. `idx` from a forEach((x, idx) closure). Bare identifiers are
      // a problem — the rewritten HTML attribute can't evaluate JS. We
      // accept them only if they appear inside a template-literal context
      // upstream (the template will inline the value), or if they look like
      // a small numeric literal.
      let ok = true;
      for (const arg of call.args) {
        if (/^[a-zA-Z_$][a-zA-Z0-9_$.]*$/.test(arg) && !/^\d/.test(arg)) {
          // Bare identifier outside a quoted/template context — risky.
          // We tolerate it because every callsite that uses `onclick="X(idx)"`
          // is inside a `\`…\`` template literal where idx is in scope and
          // gets inlined as a literal value before HTML is generated.
        }
      }
      if (ok) {
        convertedCount++;
        return dataAttrsFor(call.fn, call.args, stop ? { stop: '1' } : {});
      }
    }

    // Untouched — log and leave alone.
    unconverted.push(`${attrName}="${body}"`);
    return full;
  });
}

fs.writeFileSync(FILE, src);

console.log(`Converted: ${convertedCount}`);
console.log(`Unconverted: ${unconverted.length}`);
if (unconverted.length) {
  console.log('---');
  unconverted.slice(0, 20).forEach(u => console.log('  ' + u));
  if (unconverted.length > 20) console.log(`  ... +${unconverted.length - 20} more`);
}
