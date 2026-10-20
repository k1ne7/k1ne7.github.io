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
const typedRoot = path.dirname(path.dirname(require.resolve('typed.js')));
const typedTarget = path.join(__dirname, '..', 'source', 'vendor', 'typed');
fs.mkdirSync(typedTarget, { recursive: true });
fs.copyFileSync(path.join(typedRoot, 'dist', 'typed.umd.js'), path.join(typedTarget, 'typed.umd.js'));
fs.copyFileSync(path.join(typedRoot, 'LICENSE.txt'), path.join(typedTarget, 'LICENSE.txt'));
