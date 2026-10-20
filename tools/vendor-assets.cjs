// Serve icon CSS and font files from Pages instead of a third-party CDN.
const fs = require('node:fs');
const path = require('node:path');
const packageRoot = path.dirname(require.resolve('@fortawesome/fontawesome-free/package.json'));
const targetRoot = path.join(__dirname, '..', 'source', 'vendor', 'fontawesome');
for (const folder of ['css', 'webfonts']) {
  const target = path.join(targetRoot, folder);
  fs.mkdirSync(target, { recursive: true });
  for (const file of fs.readdirSync(path.join(packageRoot, folder))) {
    fs.copyFileSync(path.join(packageRoot, folder, file), path.join(target, file));
  }
}
fs.copyFileSync(path.join(packageRoot, 'LICENSE.txt'), path.join(targetRoot, 'LICENSE.txt'));
