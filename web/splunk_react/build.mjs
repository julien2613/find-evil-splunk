// Bundle le renderer A2UI React (+ @splunk/react-ui) en IIFE autonome
// pour chargement par un dashboard Splunk (attribut script=).
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
    logLevel: 'info',
});

console.log('Bundle écrit:', OUT);
