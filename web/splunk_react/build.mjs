// Bundle the A2UI React renderer (+ @splunk/react-ui) as a standalone IIFE
// to be loaded by a Splunk dashboard (script= attribute).
import { build } from 'esbuild';
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const OUT = resolve(
    __dirname,
    '../../splunk_app/find_evil/appserver/static/a2ui_react.js'
);

await build({
    entryPoints: [resolve(__dirname, 'src/a2ui_app.jsx')],
    bundle: true,
    outfile: OUT,
    format: 'iife',
    platform: 'browser',
    target: ['es2017'],
    minify: true,
    sourcemap: false,
    loader: { '.js': 'jsx', '.jsx': 'jsx' },
    jsx: 'automatic',
    define: { 'process.env.NODE_ENV': '"production"' },
    // Splunk loads this bundle via RequireJS. We shadow `define`/`module`/`exports`
    // inside the bundle scope so UMD dependencies (React, styled-components) take the
    // "global" branch and do NOT register an anonymous AMD define()
    // (otherwise "Mismatched anonymous define()" + dashboard error toast).
    banner: { js: '(function(){var define=void 0,module=void 0,exports=void 0;' },
    footer: { js: '})();' },
    logLevel: 'info',
});

console.log('Bundle written:', OUT);
