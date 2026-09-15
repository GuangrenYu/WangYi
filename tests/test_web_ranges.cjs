// UI logic tests with a DOM stub; this is not a browser rendering test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const elements = new Map();
function element(selector) {
  if (!elements.has(selector)) elements.set(selector, {
    value: selector === '#range-mode' ? 'all' : selector.includes('name=mode') ? 'full' : '1',
    checked: false, style: {}, textContent: '', innerHTML: '', handlers: {},
    addEventListener(name, fn) { this.handlers[name] = fn; },
    classList: {add(){},remove(){},toggle(){}},
  });
  return elements.get(selector);
}
const context = vm.createContext({
  document: {querySelector: element, querySelectorAll: () => []},
  fetch: () => new Promise(() => {}), console,
});
vm.runInContext(fs.readFileSync('cve_hunter/static/app.js', 'utf8'), context);
async function run() {
  await vm.runInContext(`renderFiles([{name:'CVE-2025-0001.txt',text:async()=> 'CVE-2025-0001 cve-2025-0002 CVE-2025-0003'}])`, context);
  assert.equal(Number(element('#range-count').max), 3);
  element('#range-mode').value='slice';
  element('#range-start').value='3';
  element('#range-start').handlers.input();
  assert.equal(Number(element('#range-end').value), 3);
  assert.equal(Number(element('#range-start-slider').value), 3);
  element('#range-end-slider').value='2';
  element('#range-end-slider').handlers.input();
  assert.equal(Number(element('#range-start').value), 2);
  assert.equal(Number(element('#range-end').value), 2);
  element('#range-count-value').value='999';
  element('#range-count-value').handlers.input();
  assert.equal(Number(element('#range-count').value), 3);
  element('#range-count').value='1';
  element('#range-count').handlers.input();
  assert.equal(Number(element('#range-count-value').value), 1);
  element('#range-mode').value='all';
  element('#range-mode').handlers.change();
  assert.equal(element('#range-slice-row').hidden, true);
  assert.equal(element('#range-count-row').hidden, true);
  element('#environment-discovery').checked=true;
  element('#environment-discovery').handlers.change();
  assert.equal(element('#docker-enabled').disabled, false);
  element('#local-only').checked=true;
  element('#local-only').handlers.change();
  assert.equal(element('#environment-discovery').checked, false);
  assert.equal(element('#docker-enabled').disabled, true);
  await vm.runInContext('renderFiles([])',context);
  assert.equal(element('#range-count').disabled,true);
  // A slower, obsolete file read cannot overwrite the current selection.
  console.log('Range bounds, bidirectional M/N controls, count deduplication, and offline options passed');
}
run().catch(error=>{console.error(error);process.exitCode=1;});
