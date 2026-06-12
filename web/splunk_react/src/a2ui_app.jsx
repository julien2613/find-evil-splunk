/**
 * Renderer A2UI natif Splunk — composants @splunk/react-ui.
 * Fetch le flux A2UI JSONL (serveur a2ui_server) et mappe les composants
 * abstraits A2UI vers les composants React de Splunk.
 *
 * Monté dans un dashboard Splunk via l'attribut script= sur le div #a2ui-root.
 */
import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import { SplunkThemeProvider } from '@splunk/themes';
import Card from '@splunk/react-ui/Card';
import Heading from '@splunk/react-ui/Heading';
import Paragraph from '@splunk/react-ui/Paragraph';
import Markdown from '@splunk/react-ui/Markdown';

// Par défaut : snapshot servi par Splunk (MÊME origine → pas de souci CORS/CSP).
// Fallback live possible via window.A2UI_SRC = "http://localhost:8801/a2ui/forensic_report".
const A2UI_SRC =
    (typeof window !== 'undefined' && window.A2UI_SRC) ||
    '/static/app/find_evil/forensic_report.a2ui.json';

const SEV_COLOR = {
    critical: '#ff5b5b',
    high: '#ff9d3c',
    medium: '#ffe03c',
    low: '#3cff9d',
    informational: '#3cb4ff',
    unknown: '#8a8a9a',
};

function miniMarkdown(s) {
    const esc = (s || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    return esc
        .replace(/^### (.*)$/gm, '<b>$1</b>')
        .replace(/^## (.*)$/gm, "<b style='color:#5fa8ff'>$1</b>")
        .replace(/^# (.*)$/gm, "<b style='color:#5fa8ff;font-size:16px'>$1</b>")
        .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
        .replace(/^- (.*)$/gm, '• $1')
        .replace(/\n/g, '<br/>');
}

// Résolution JSON Pointer (RFC 6901) dans le contexte de données courant (scope).
function resolvePath(ctx, pointer) {
    if (!pointer || pointer === '/') return ctx;
    let cur = ctx;
    pointer.split('/').slice(1).forEach((seg) => {
        seg = seg.replace(/~1/g, '/').replace(/~0/g, '~');
        cur = cur == null ? cur : cur[seg];
    });
    return cur;
}

// DynamicString : littéral (string) ou data binding ({path}).
function resolveString(ctx, val) {
    if (typeof val === 'object' && val && 'path' in val) {
        const v = resolvePath(ctx, val.path);
        return v == null ? '' : String(v);
    }
    return val == null ? '' : String(val);
}

// Enfants : tableau statique d'ids OU template {componentId, path} (ChildList A2UI).
function childNodes(children, map, ctx, key) {
    if (Array.isArray(children)) {
        return children.map((cid) => renderNode(cid, map, ctx, key + ':' + cid));
    }
    if (children && children.componentId && children.path) {
        const arr = resolvePath(ctx, children.path) || [];
        // Template : rend componentId une fois par item, paths scopés à l'item.
        return arr.map((item, i) => renderNode(children.componentId, map, item, key + ':tmpl:' + i));
    }
    return null;
}

// Mappe un composant A2UI -> élément React Splunk. ctx = data model courant (scope).
function renderNode(id, map, ctx, key) {
    const c = map[id];
    if (!c) return null;
    const t = c.component;
    const k = key || id;

    if (t === 'Column') {
        return <div key={k} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {childNodes(c.children, map, ctx, k)}</div>;
    }
    if (t === 'Row') {
        return <div key={k} style={{ display: 'flex', flexDirection: 'row', gap: 14, flexWrap: 'wrap' }}>
            {childNodes(c.children, map, ctx, k)}</div>;
    }
    if (t === 'List') {
        return <div key={k} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {childNodes(c.children, map, ctx, k)}</div>;
    }
    if (t === 'Card') {
        return (
            <Card key={k} style={{ flex: 1 }}>
                <Card.Body>{c.child ? renderNode(c.child, map, ctx, k + ':' + c.child) : null}</Card.Body>
            </Card>
        );
    }
    if (t === 'Text') {
        const v = c.variant || 'body';
        const txt = resolveString(ctx, c.text);
        if (id === 'verdict_text') {
            return (
                <span key={k} style={{ display: 'inline-block', padding: '8px 16px', borderRadius: 8,
                    background: '#fde7e7', color: '#d41f1f', border: '1px solid #f5c2c2',
                    fontWeight: 800, fontSize: 20 }}>{txt}</span>
            );
        }
        const m = /^h([1-5])$/.exec(v);  // variant ∈ {h1..h5, caption, body}
        if (m) return <Heading key={k} level={Number(m[1])}>{txt}</Heading>;
        if (v === 'caption')
            return <Paragraph key={k} style={{ fontSize: 12, color: '#8a8a9a' }}>{txt}</Paragraph>;
        return <Markdown key={k} text={txt} />;  // text supporte le markdown nativement
    }
    return <div key={k}>[{t}]</div>;
}

function parseA2UI(text) {
    const map = {};
    let dataModel = {};
    let root = null;
    text.split('\n').forEach((line) => {
        line = line.trim();
        if (!line) return;
        let msg;
        try {
            msg = JSON.parse(line);
        } catch (e) {
            return;
        }
        if (msg.updateComponents) {
            (msg.updateComponents.components || []).forEach((comp) => {
                map[comp.id] = comp;
            });
            if (!root && map.root) root = 'root';
        }
        if (msg.updateDataModel) {
            // Applique la valeur au chemin indiqué (RFC 6901). "/" remplace le modèle.
            const dm = msg.updateDataModel;
            if (!dm.path || dm.path === '/') {
                dataModel = dm.value;
            } else {
                const segs = dm.path.split('/').slice(1);
                let cur = dataModel;
                segs.slice(0, -1).forEach((s) => { cur = cur[s] = cur[s] || {}; });
                cur[segs[segs.length - 1]] = dm.value;
            }
        }
        if (msg.deleteSurface) {
            Object.keys(map).forEach((k) => delete map[k]);
            dataModel = {};
            root = null;
        }
    });
    return { map, root, dataModel };
}

function App() {
    const [state, setState] = useState({ status: 'loading', map: {}, root: null, dataModel: {}, count: 0 });

    useEffect(() => {
        fetch(A2UI_SRC)
            .then((r) => {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.text();
            })
            .then((text) => {
                const { map, root, dataModel } = parseA2UI(text);
                setState({ status: 'ok', map, root, dataModel, count: Object.keys(map).length });
            })
            .catch((e) => setState({ status: 'error', error: e.message, map: {}, root: null, dataModel: {}, count: 0 }));
    }, []);

    return (
        <SplunkThemeProvider family="prisma" colorScheme="light" density="comfortable">
            <div style={{ padding: 8 }}>
                {state.status === 'loading' && <Paragraph>Chargement du rapport A2UI…</Paragraph>}
                {state.status === 'error' && (
                    <Paragraph>
                        ⚠ Impossible de charger A2UI depuis {A2UI_SRC} : {state.error}. Démarre le
                        serveur (uvicorn a2ui_server:app --port 8801).
                    </Paragraph>
                )}
                {state.status === 'ok' && (
                    <div>
                        <Paragraph style={{ color: '#8a8a9a', fontSize: 13 }}>
                            Rendu via composants @splunk/react-ui — {state.count} composants A2UI
                            (protocole Agent-to-UI v0.9).
                        </Paragraph>
                        {state.root && renderNode(state.root, state.map, state.dataModel, state.root)}
                    </div>
                )}
            </div>
        </SplunkThemeProvider>
    );
}

function doMount() {
    const el = document.getElementById('a2ui-root');
    if (el && !el.getAttribute('data-mounted')) {
        el.setAttribute('data-mounted', '1');
        ReactDOM.render(<App />, el);
    }
}

function pollMount() {
    // Fallback : attend le div (panneaux rendus en asynchrone).
    let tries = 0;
    const timer = setInterval(() => {
        if (document.getElementById('a2ui-root')) {
            doMount();
            clearInterval(timer);
        } else if (++tries > 100) {
            clearInterval(timer);
        }
    }, 100);
}

// Idiomatique Splunk : attendre que le dashboard SimpleXML soit prêt.
if (typeof window !== 'undefined' && typeof window.require === 'function') {
    try {
        window.require(['splunkjs/mvc/simplexml/ready!'], function () {
            doMount();
        });
    } catch (e) {
        pollMount();
    }
} else {
    pollMount();
}

export default App;
