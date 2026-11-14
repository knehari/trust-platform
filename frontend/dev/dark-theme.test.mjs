import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { OUTPUT, buildDarkTheme, currentSources, darkColor } from './dark-theme.mjs';

test('light surfaces turn dark and dark ink turns light', () => {
  assert.notEqual(darkColor('#ffffff', 'background'), '#ffffff');
  assert.ok(parseInt(darkColor('#ffffff', 'background').slice(1, 3), 16) < 0x40);
  assert.ok(parseInt(darkColor('#172b45', 'color').slice(1, 3), 16) > 0xc0);
  // Mid-tone accents stay as fills but brighten as text.
  assert.equal(darkColor('#1f7a6d', 'background'), '#1f7a6d');
  assert.notEqual(darkColor('#1f7a6d', 'color'), '#1f7a6d');
});

test('the dark theme is scoped and keeps dark-by-design surfaces', () => {
  const css = buildDarkTheme(['.panel{background:#fff;color:#172b45} .sidebar{background:#0c1b2d} @media(max-width:9px){.x{border:1px solid #e2e8ee}}']);
  assert.match(css, /:root\[data-theme="dark"\] \.panel \{ background: #/u);
  assert.doesNotMatch(css, /\.sidebar/u);
  assert.match(css, /@media\(max-width:9px\) \{/u);
});

test('src/theme-dark.css is up to date with the stylesheets', () => {
  assert.equal(readFileSync(OUTPUT, 'utf8'), buildDarkTheme(currentSources()), 'Run: node dev/dark-theme.mjs');
});
