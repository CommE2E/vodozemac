#!/usr/bin/env node

import {readFileSync, writeFileSync} from 'fs';

const wasmLoaderPath = new URL('../wasm/vodozemac.js', import.meta.url);
let content = readFileSync(wasmLoaderPath, 'utf-8');

// Node.js has a fetch implementation that doesn't support fetching local files.
// We need the WASM loader to load from node_modules, so we have to monkey-patch
// the WASM loader to use Node.js filesystem utilities instead in this case.
// This matches the if block containing the only fetch() call in the file.
const fetchCallPattern =
  /if \(typeof module_or_path === 'string'.*?fetch\(module_or_path\);.*?\n    \}/s;

const replacement = `
if (
  typeof module_or_path === 'string' ||
  (typeof Request === 'function' &&
    module_or_path instanceof Request) ||
  (typeof URL === 'function' &&
    module_or_path instanceof URL)
) {
  // Node.js fetch polyfill for file:// URLs
  if (
    typeof process !== 'undefined' &&
    process.versions &&
    process.versions.node &&
    module_or_path instanceof URL &&
    module_or_path.protocol === 'file:'
  ) {
    const fs = await import('fs');
    const url = await import('url');
    const filePath = url.fileURLToPath(module_or_path);
    const buffer = fs.readFileSync(filePath);
    module_or_path = Promise.resolve(buffer);
  } else {
    module_or_path = fetch(module_or_path);
  }
}
`;

content = content.replace(fetchCallPattern, replacement);

writeFileSync(wasmLoaderPath, content, 'utf-8');
console.log('✓ Patched vodozemac.js with Node.js fetch polyfill');
