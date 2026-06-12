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

// Mappe un composant A2UI -> élément React Splunk
function renderNode(id, map, depth = 0) {
    const c = map[id];
    if (!c) return null;
    const t = c.component;
    const kids = (c.children || []).map((cid) => renderNode(cid, map, depth + 1));

    if (t === 'Column') {
        return (
            <div key={id} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {kids}
            </div>
        );
    }
    if (t === 'Row') {
        return (
            <div key={id} style={{ display: 'flex', flexDirection: 'row', gap: 14, flexWrap: 'wrap' }}>
                {kids}
            </div>
        );
    }
    if (t === 'List') {
        return (
            <div key={id} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {kids}
            </div>
        );
    }
    if (t === 'Card') {
        const child = c.child ? renderNode(c.child, map, depth + 1) : null;
        const sevChild = map[c.child];
        const accent =
            sevChild && sevChild.severity ? SEV_COLOR[sevChild.severity] || '#3a506b' : null;
        return (
            <Card key={id} style={accent ? { flex: 1, borderLeft: `4px solid ${accent}` } : { flex: 1 }}>
                <Card.Body>
                    {child}
                    {kids}
                </Card.Body>
            </Card>
        );
    }
    if (t === 'Text') {
        const v = c.variant || 'body';
        const txt = typeof c.text === 'object' ? JSON.stringify(c.text) : c.text || '';
        if (id === 'verdict_text') {
            return (
                <span
                    key={id}
                    style={{
                        display: 'inline-block',
                        padding: '8px 16px',
                        borderRadius: 8,
                        background: '#3a0d0d',
                        color: '#ff5b5b',
                        fontWeight: 800,
                        fontSize: 20,
                    }}
                >
                    {txt}
                </span>
            );
        }
        // variant ∈ {h1..h5, caption, body} (catalogue A2UI v0.9). Les titres -> Heading.
        const m = /^h([1-5])$/.exec(v);
        if (m) return <Heading key={id} level={Number(m[1])}>{txt}</Heading>;
        if (v === 'caption')
            return <Paragraph key={id} style={{ fontSize: 12, color: '#8a8a9a' }}>{txt}</Paragraph>;
        // body (défaut) — le texte A2UI supporte le markdown nativement.
        return <Markdown key={id} text={txt} />;
    }
    return <div key={id}>[{t}]</div>;
}

function parseA2UI(text) {
    const map = {};
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
            const uc = msg.updateComponents;
            if (uc.root) root = uc.root;
            (uc.components || []).forEach((comp) => {
                map[comp.id] = comp;
            });
            if (!root && map.root) root = 'root';
        }
        if (msg.deleteSurface) {
            Object.keys(map).forEach((k) => delete map[k]);
            root = null;
        }
    });
    return { map, root };
}

function App() {
    const [state, setState] = useState({ status: 'loading', map: {}, root: null, count: 0 });

    useEffect(() => {
        fetch(A2UI_SRC)
            .then((r) => {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.text();
            })
            .then((text) => {
                const { map, root } = parseA2UI(text);
                setState({ status: 'ok', map, root, count: Object.keys(map).length });
            })
            .catch((e) => setState({ status: 'error', error: e.message, map: {}, root: null, count: 0 }));
    }, []);

    return (
        <SplunkThemeProvider family="prisma" colorScheme="dark" density="comfortable">
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
                        {state.root && renderNode(state.root, state.map)}
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
