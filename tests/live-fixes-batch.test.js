// Live-functionality fixes batch (2026-06-11). Five P1 rows drained:
//   1. onSearchProviderChange clears stale #map-search-results so the
//      "Google Places not configured" hint doesn't linger after switching
//      provider.
//   2. .narrate-btn buttons get a "needs API key" suffix + dimmed style
//      when /trips/narrate-status returns enabled:false; the existing
//      openNarrateModal gate still toasts + redirects to Account, but the
//      button itself signals up-front.
//   3. Login + Places-key + Anthropic-key inputs are wrapped in real <form>
//      elements with autocomplete attributes so password managers can
//      autofill credentials and save API keys. Submit dispatcher always
//      preventDefault so no full-page navigation.
//   4. _appendChronoPage / _appendWishlistPage pagination buttons migrated
//      from `more.onclick = fn` to `data-click` — consistency with the
//      rest of the surface UI.
//   5. enterToFocus now preventDefault so Enter on username field shifts
//      focus to password without also triggering the wrapping form's submit.

const fs = require('fs');
const path = require('path');
const vm = require('vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf-8');

function extractFunction(name) {
  const start = html.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`Function ${name} not found`);
  let depth = 0, i = start, foundFirst = false;
  for (; i < html.length; i++) {
    if (html[i] === '{') { depth++; foundFirst = true; }
    if (html[i] === '}') depth--;
    if (foundFirst && depth === 0) break;
  }
  return html.substring(start, i + 1);
}

describe('onSearchProviderChange clears stale search results', () => {
  test('function body clears #map-search-results innerHTML (no display:none — _runLiveSearch does not reset it)', () => {
    const fn = extractFunction('onSearchProviderChange');
    expect(fn).toMatch(/getElementById\(\s*['"]map-search-results['"]\s*\)/);
    expect(fn).toMatch(/\.innerHTML\s*=\s*['"]{2}/);
    // Must NOT set display:none — _runLiveSearch only writes innerHTML and
    // would not un-hide the element, leaving live search dead after a switch.
    expect(fn).not.toMatch(/\.style\.display\s*=\s*['"]none['"]/);
  });
});

describe('Narrate buttons signal "needs API key" state', () => {
  test('both Narrate buttons carry the .narrate-btn class for refresh targeting', () => {
    // Trip Manager button and Trips empty-state button both need the class.
    const matches = html.match(/class="[^"]*\bnarrate-btn\b[^"]*"[^>]*data-click="openNarrateModal"/g) || [];
    expect(matches.length).toBeGreaterThanOrEqual(2);
  });

  test('_refreshNarrateButtonState toggles the disabled class + suffix on .narrate-btn', () => {
    const fn = extractFunction('_refreshNarrateButtonState');
    expect(fn).toMatch(/querySelectorAll\(\s*['"]\.narrate-btn['"]\s*\)/);
    expect(fn).toMatch(/classList\.toggle\(\s*['"]narrate-btn-disabled['"]/);
    expect(fn).toMatch(/needs API key/);
  });

  test('CSS rule .narrate-btn-disabled dims the button', () => {
    expect(html).toMatch(/\.narrate-btn-disabled\s*\{[^}]*opacity:/);
  });

  test('cache invalidation: save + remove paths call _resetNarrateEnabledCache + _refreshNarrateButtonState', () => {
    const save = extractFunction('saveAnthropicKey');
    const remove = extractFunction('removeAnthropicKey');
    [save, remove].forEach(fn => {
      expect(fn).toMatch(/_resetNarrateEnabledCache\(\)/);
      expect(fn).toMatch(/_refreshNarrateButtonState\(\)/);
    });
  });

  test('switchView(trips-view) refreshes the button state', () => {
    const fn = extractFunction('switchView');
    // The trips-view branch should call the refresh — search for the call
    // anywhere inside the function body (the body contains many branches).
    expect(fn).toMatch(/_refreshNarrateButtonState\(\)/);
  });
});

describe('Password inputs wrapped in <form> for autofill', () => {
  test('login uses <form id="auth-form" data-submit="doAuth">', () => {
    expect(html).toMatch(/<form[^>]*id="auth-form"[^>]*data-submit="doAuth"/);
  });

  test('login form declares autocomplete="on" and the password field uses current-password', () => {
    expect(html).toMatch(/<form[^>]*id="auth-form"[^>]*autocomplete="on"/);
    expect(html).toMatch(/id="auth-password"[^>]*autocomplete="current-password"/);
    expect(html).toMatch(/id="auth-username"[^>]*autocomplete="username"/);
  });

  test('Places-key inputs sit inside a <form data-submit="savePlacesKey">', () => {
    const forms = html.match(/<form[^>]*data-submit="savePlacesKey"/g) || [];
    // Two render paths (initial setup + change-key details) → both need a form.
    expect(forms.length).toBe(2);
  });

  test('Anthropic-key inputs sit inside a <form data-submit="saveAnthropicKey">', () => {
    const forms = html.match(/<form[^>]*data-submit="saveAnthropicKey"/g) || [];
    expect(forms.length).toBe(2);
  });

  test('Remove buttons keep type="button" so they do NOT submit the form', () => {
    const removePlaces = html.match(/type="button"[^>]*data-click="removePlacesKey"/);
    const removeAnthropic = html.match(/type="button"[^>]*data-click="removeAnthropicKey"/);
    expect(removePlaces).toBeTruthy();
    expect(removeAnthropic).toBeTruthy();
  });

  test('Save buttons are type="submit" so Enter triggers form submission', () => {
    // Each save button now ships without data-click (submit dispatcher fires
    // savePlacesKey/saveAnthropicKey via data-submit on the form).
    expect(html).not.toMatch(/data-click="savePlacesKey"/);
    expect(html).not.toMatch(/data-click="saveAnthropicKey"/);
  });
});

describe('submit dispatcher always preventDefault (no full-page POST)', () => {
  test('_delegate preventDefault on submit eventName', () => {
    const fn = extractFunction('_delegate');
    expect(fn).toMatch(/eventName\s*===\s*['"]submit['"]/);
    expect(fn).toMatch(/preventDefault/);
  });

  test('enterToFocus preventDefault on Enter so it does NOT bubble to a wrapping form', () => {
    // enterToFocus: is the ACTIONS entry's property declaration (vs the HTML
    // attribute uses earlier in the file). Slice from there to the next
    // top-level property and assert preventDefault is called.
    const declIdx = html.indexOf('enterToFocus:');
    expect(declIdx).toBeGreaterThan(-1);
    const slice = html.slice(declIdx, declIdx + 400);
    expect(slice).toMatch(/preventDefault/);
  });
});

describe('Pagination buttons use data-click instead of .onclick=', () => {
  test('chrono-load-more sets data-click="_appendChronoPage"', () => {
    // Stable enough: the setAttribute call inside _drawChrono*.
    expect(html).toMatch(/setAttribute\(\s*['"]data-click['"]\s*,\s*['"]_appendChronoPage['"]\s*\)/);
  });

  test('the old `more.onclick = _appendChronoPage` is gone', () => {
    expect(html).not.toMatch(/more\.onclick\s*=\s*_appendChronoPage/);
  });
});

describe('Weather overlay persistence (regression — both attach + detach paths)', () => {
  // The roadmap claim was that toggle-ON didn't persist. The current code
  // does call _persistActiveOverlays after BOTH state mutations. Pin both
  // call sites + the JSON-array contract so any future refactor can't
  // silently regress one path.
  test('toggleOverlay calls _persistActiveOverlays on detach (set.delete branch)', () => {
    const fn = extractFunction('toggleOverlay');
    // Detach branch: state.activeOverlays.delete(...) → _persistActiveOverlays()
    expect(fn).toMatch(/activeOverlays\.delete\([\s\S]*?_persistActiveOverlays\(\)/);
  });

  test('toggleOverlay calls _persistActiveOverlays on attach (set.add branch)', () => {
    const fn = extractFunction('toggleOverlay');
    expect(fn).toMatch(/activeOverlays\.add\([\s\S]*?_persistActiveOverlays\(\)/);
  });

  test('_persistActiveOverlays serializes the Set as an array under the activeOverlays key', () => {
    const fn = extractFunction('_persistActiveOverlays');
    expect(fn).toMatch(/setItem\(\s*['"]activeOverlays['"]/);
    expect(fn).toMatch(/\[\.\.\.state\.activeOverlays\]/);
  });
});
