const fs = require('node:fs');
const path = require('node:path');

const docsTemplatePath = path.join(__dirname, 'docs.html');
function renderDocs(baseURL) {
  try {
    const template = fs.readFileSync(docsTemplatePath, 'utf8');
    return template.replaceAll('{{BASE_URL}}', baseURL);
  } catch (e) {
    console.error('Failed reading docs.html:', e);
    return '<h1>Error loading documentation</h1>';
  }
}

module.exports = {
  renderDocs
};
