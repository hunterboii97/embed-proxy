const fs = require('node:fs');
const path = require('node:path');

const docsTemplatePath = path.join(__dirname, 'docs.html');
function renderDocs(baseURL) {
  try {
    const template = fs.readFileSync(docsTemplatePath, 'utf8');
    // Injected into a JS string literal: JSON-encode and neutralise the
    // characters that can terminate the literal or the <script> block.
    const json = JSON.stringify(String(baseURL))
      .replace(/</g, '\\u003c')
      .replace(/>/g, '\\u003e')
      .replace(/&/g, '\\u0026')
      .replace(/\u2028/g, '\\u2028')
      .replace(/\u2029/g, '\\u2029');
    return template.replaceAll('{{BASE_URL_JSON}}', json);
  } catch (e) {
    console.error('Failed reading docs.html:', e);
    return '<h1>Error loading documentation</h1>';
  }
}

module.exports = {
  renderDocs
};
