const fs = require('node:fs');
const path = require('node:path');

const docsTemplatePath = path.join(__dirname, 'docs.html');
let docsHtmlTemplate = '';

try {
  docsHtmlTemplate = fs.readFileSync(docsTemplatePath, 'utf8');
} catch (e) {
  console.error('Failed reading docs.html:', e);
}

function renderDocs(baseURL) {
  return docsHtmlTemplate.replaceAll('{{BASE_URL}}', baseURL);
}

module.exports = {
  renderDocs
};
