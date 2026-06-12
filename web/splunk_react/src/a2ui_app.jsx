/**
 * Renderer A2UI → composants natifs Splunk (@splunk/react-ui).
 *
 * L'agent officiel splunklib.ai émet un document A2UI (https://a2ui.org) avec un
 * catalogue de composants ENRICHI, orienté information : VerdictBadge, KpiRow,
 * SeverityBar, TechniqueTable (chips de sévérité), RecommendationList, IncidentList,
 * LolbinBars, Collapsible. Ce module mappe chaque composant A2UI vers un contrôle
 * @splunk/react-ui dense, plutôt que de déverser du Markdown verbeux.
 *
 * Montage : tout <div data-a2ui-src="/static/app/find_evil/<surface>.a2ui.json">
 * présent dans un dashboard SimpleXML est rendu avec le snapshot indiqué.
 */
import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import { SplunkThemeProvider } from '@splunk/themes';
import Card from '@splunk/react-ui/Card';
import Heading from '@splunk/react-ui/Heading';
import Paragraph from '@splunk/react-ui/Paragraph';
import Markdown from '@splunk/react-ui/Markdown';
import Table from '@splunk/react-ui/Table';

// --- Référentiel de sévérité (couleurs + libellés FR) ---
const SEV = {
    critical: { label: 'Critique', color: '#d41f1f', bg: '#fde7e7', fg: '#a01313' },
    high: { label: 'Élevée', color: '#f79009', bg: '#fff3e0', fg: '#9a5b00' },
    medium: { label: 'Moyenne', color: '#eab308', bg: '#fef9e7', fg: '#7a5c00' },
    low: { label: 'Faible', color: '#12b76a', bg: '#e7f7ee', fg: '#0a6b3d' },
    informational: { label: 'Info', color: '#2e90fa', bg: '#e8f2ff', fg: '#0b4a9a' },
    unknown: { label: '—', color: '#98a2b3', bg: '#eef1f6', fg: '#475467' },
};
const sevOf = (s) => SEV[String(s || '').toLowerCase()] || SEV.unknown;

const VERDICT_TONE = {
    COMPROMIS: { color: '#d41f1f', bg: '#fde7e7', fg: '#a01313', icon: '🔴' },
    SUSPECT: { color: '#f79009', bg: '#fff3e0', fg: '#9a5b00', icon: '🟠' },
    RAS: { color: '#12b76a', bg: '#e7f7ee', fg: '#0a6b3d', icon: '🟢' },
};
const verdictTone = (v) => {
    const k = String(v || '').toUpperCase();
    if (k.includes('COMPROMIS')) return VERDICT_TONE.COMPROMIS;
    if (k.includes('SUSPECT')) return VERDICT_TONE.SUSPECT;
    if (k.includes('RAS')) return VERDICT_TONE.RAS;
    return VERDICT_TONE.SUSPECT;
};

// --- Résolution JSON Pointer (RFC 6901) dans le scope de données courant ---
function resolvePath(ctx, pointer) {
    if (!pointer || pointer === '/') return ctx;
    let cur = ctx;
    pointer.split('/').slice(1).forEach((seg) => {
        seg = seg.replace(/~1/g, '/').replace(/~0/g, '~');
        cur = cur == null ? cur : cur[seg];
    });
    return cur;
}
// DynamicString : littéral ou data binding {path}
function dyn(ctx, val) {
    if (val && typeof val === 'object' && 'path' in val) {
        const v = resolvePath(ctx, val.path);
        return v == null ? '' : v;
    }
    return val == null ? '' : val;
}
// Récupère un tableau lié par la prop `path` du composant
function boundArray(ctx, c) {
    const v = c.path ? resolvePath(ctx, c.path) : c.items;
    return Array.isArray(v) ? v : [];
}

// ============ Contrôles custom (@splunk/react-ui) ============

function SevChip({ sev }) {
    const s = sevOf(sev);
    return (
        <span style={{ display: 'inline-block', padding: '2px 10px', borderRadius: 999,
            fontSize: 11, fontWeight: 700, letterSpacing: 0.3, textTransform: 'uppercase',
            background: s.bg, color: s.fg, border: `1px solid ${s.color}33` }}>{s.label}</span>
    );
}

function VerdictBadge({ verdict, summary }) {
    const t = verdictTone(verdict);
    return (
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 20px',
            background: t.bg, border: `1px solid ${t.color}40`, borderLeft: `6px solid ${t.color}`,
            borderRadius: 12 }}>
            <div style={{ fontSize: 26 }}>{t.icon}</div>
            <div>
                <div style={{ fontSize: 22, fontWeight: 800, color: t.fg, lineHeight: 1.1 }}>
                    Verdict : {String(verdict).replace(/^Verdict\s*:\s*/i, '')}
                </div>
                {summary ? <div style={{ fontSize: 13, color: '#475467', marginTop: 4 }}>{summary}</div> : null}
            </div>
        </div>
    );
}

const KPI_TONE = {
    critical: '#d41f1f', high: '#f79009', neutral: '#0b1f3a', info: '#0877a6', good: '#12b76a',
};
function KpiRow({ items }) {
    return (
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {items.map((k, i) => (
                <Card key={i} style={{ flex: '1 1 140px', minWidth: 130 }}>
                    <Card.Body>
                        <div style={{ fontSize: 12, color: '#667085', fontWeight: 600,
                            textTransform: 'uppercase', letterSpacing: 0.3 }}>{k.label}</div>
                        <div style={{ fontSize: 30, fontWeight: 800,
                            color: KPI_TONE[k.tone] || KPI_TONE.neutral, lineHeight: 1.1 }}>{k.value}</div>
                    </Card.Body>
                </Card>
            ))}
        </div>
    );
}

function SeverityBar({ data }) {
    const total = data.reduce((a, d) => a + (Number(d.count) || 0), 0) || 1;
    return (
        <div>
            <div style={{ display: 'flex', height: 26, borderRadius: 8, overflow: 'hidden',
                border: '1px solid #e4e8f0' }}>
                {data.map((d, i) => {
                    const s = sevOf(d.sev);
                    const w = (Number(d.count) || 0) / total * 100;
                    return w > 0 ? (
                        <div key={i} title={`${s.label} : ${d.count}`} style={{ width: `${w}%`,
                            background: s.color, display: 'flex', alignItems: 'center',
                            justifyContent: 'center', color: '#fff', fontSize: 11, fontWeight: 700 }}>
                            {w > 8 ? d.count : ''}
                        </div>
                    ) : null;
                })}
            </div>
            <div style={{ display: 'flex', gap: 16, marginTop: 8, flexWrap: 'wrap' }}>
                {data.map((d, i) => {
                    const s = sevOf(d.sev);
                    return (
                        <span key={i} style={{ fontSize: 12, color: '#475467', display: 'flex',
                            alignItems: 'center', gap: 6 }}>
                            <span style={{ width: 10, height: 10, borderRadius: 3, background: s.color,
                                display: 'inline-block' }} />
                            {s.label} <b style={{ color: '#1d2939' }}>{d.count}</b>
                        </span>
                    );
                })}
            </div>
        </div>
    );
}

function TechniqueTable({ rows }) {
    return (
        <Table stripeRows>
            <Table.Head>
                <Table.HeadCell>Sévérité</Table.HeadCell>
                <Table.HeadCell>Signature</Table.HeadCell>
                <Table.HeadCell>MITRE ATT&CK</Table.HeadCell>
                <Table.HeadCell>Description</Table.HeadCell>
            </Table.Head>
            <Table.Body>
                {rows.map((r, i) => (
                    <Table.Row key={i}>
                        <Table.Cell><SevChip sev={r.severity} /></Table.Cell>
                        <Table.Cell><code style={{ fontSize: 12, color: '#0b1f3a' }}>{r.signature}</code></Table.Cell>
                        <Table.Cell>
                            <span style={{ fontFamily: 'monospace', fontSize: 12, color: '#b42318' }}>
                                {r.mitre || '—'}</span>
                        </Table.Cell>
                        <Table.Cell><span style={{ fontSize: 13, color: '#344054' }}>{r.description}</span></Table.Cell>
                    </Table.Row>
                ))}
            </Table.Body>
        </Table>
    );
}

function RecommendationList({ items }) {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {items.map((r, i) => (
                <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start',
                    padding: '10px 14px', background: '#fff', border: '1px solid #e4e8f0',
                    borderRadius: 10 }}>
                    <span style={{ flex: '0 0 auto', padding: '2px 9px', borderRadius: 6,
                        background: '#0b1f3a', color: '#fff', fontSize: 12, fontWeight: 800 }}>
                        {r.priority || `#${i + 1}`}</span>
                    <div>
                        {r.horizon ? <span style={{ fontSize: 11, fontWeight: 700, color: '#b42318',
                            textTransform: 'uppercase', letterSpacing: 0.3 }}>{r.horizon}</span> : null}
                        <div style={{ fontSize: 13, color: '#1d2939', lineHeight: 1.5 }}>{r.text}</div>
                    </div>
                </div>
            ))}
        </div>
    );
}

function LolbinBars({ data }) {
    const max = data.reduce((a, d) => Math.max(a, Number(d.count) || 0), 0) || 1;
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {data.map((d, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <code style={{ flex: '0 0 130px', fontSize: 12, color: '#0b1f3a' }}>{d.name}</code>
                    <div style={{ flex: 1, height: 18, background: '#f0f3f9', borderRadius: 6 }}>
                        <div style={{ width: `${(Number(d.count) || 0) / max * 100}%`, height: '100%',
                            background: '#7c5cff', borderRadius: 6 }} />
                    </div>
                    <b style={{ flex: '0 0 auto', fontSize: 13, color: '#1d2939' }}>{d.count}</b>
                </div>
            ))}
        </div>
    );
}

function Collapsible({ title, text, open }) {
    return (
        <details open={!!open} style={{ background: '#fff', border: '1px solid #e4e8f0',
            borderRadius: 10, padding: '8px 14px' }}>
            <summary style={{ cursor: 'pointer', fontWeight: 700, color: '#0b1f3a', fontSize: 14,
                listStyle: 'revert' }}>{title || 'Détails'}</summary>
            <div style={{ marginTop: 8, fontSize: 13, color: '#1d2939' }}>
                <Markdown text={String(text || '')} />
            </div>
        </details>
    );
}

function IncidentList({ items }) {
    return (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {items.map((inc, i) => {
                const t = verdictTone(inc.verdict);
                return (
                    <Card key={i}>
                        <Card.Body>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
                                <span style={{ padding: '4px 12px', borderRadius: 999, background: t.bg,
                                    color: t.fg, border: `1px solid ${t.color}40`, fontWeight: 800,
                                    fontSize: 13 }}>{t.icon} {inc.verdict}</span>
                                <span style={{ fontSize: 12, color: '#667085' }}>{inc.time}</span>
                                <span style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                                    <span style={{ fontSize: 12, color: '#a01313', fontWeight: 700 }}>
                                        {inc.critical} critiques</span>
                                    <span style={{ fontSize: 12, color: '#9a5b00', fontWeight: 700 }}>
                                        {inc.high} élevées</span>
                                </span>
                            </div>
                            {inc.analysis ? (
                                <div style={{ marginTop: 10 }}>
                                    <Collapsible title="Analyse IA du triage" text={inc.analysis} />
                                </div>
                            ) : null}
                        </Card.Body>
                    </Card>
                );
            })}
        </div>
    );
}

// ============ Dispatch A2UI -> contrôle ============

function childNodes(children, map, ctx, key) {
    if (Array.isArray(children)) return children.map((cid) => renderNode(cid, map, ctx, key + ':' + cid));
    if (children && children.componentId && children.path) {
        const arr = resolvePath(ctx, children.path) || [];
        return arr.map((item, i) => renderNode(children.componentId, map, item, key + ':t:' + i));
    }
    return null;
}

function renderNode(id, map, ctx, key) {
    const c = map[id];
    if (!c) return null;
    const t = c.component;
    const k = key || id;
    const block = (el) => <div key={k} style={{ marginBottom: 4 }}>{el}</div>;

    switch (t) {
        // --- Catalogue enrichi (contrôles info-denses) ---
        case 'VerdictBadge':
            return block(<VerdictBadge verdict={dyn(ctx, c.verdict)} summary={dyn(ctx, c.summary)} />);
        case 'KpiRow':
            return block(<KpiRow items={boundArray(ctx, c)} />);
        case 'SeverityBar':
            return block(<SeverityBar data={boundArray(ctx, c)} />);
        case 'TechniqueTable':
            return block(<TechniqueTable rows={boundArray(ctx, c)} />);
        case 'RecommendationList':
            return block(<RecommendationList items={boundArray(ctx, c)} />);
        case 'LolbinBars':
            return block(<LolbinBars data={boundArray(ctx, c)} />);
        case 'IncidentList':
            return block(<IncidentList items={boundArray(ctx, c)} />);
        case 'Collapsible':
            return block(<Collapsible title={dyn(ctx, c.title)} text={dyn(ctx, c.text)} open={c.open} />);

        // --- Catalogue A2UI standard (fallback conforme v0.9) ---
        case 'Column':
            return <div key={k} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {childNodes(c.children, map, ctx, k)}</div>;
        case 'Row':
            return <div key={k} style={{ display: 'flex', flexDirection: 'row', gap: 14, flexWrap: 'wrap' }}>
                {childNodes(c.children, map, ctx, k)}</div>;
        case 'List':
            return <div key={k} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {childNodes(c.children, map, ctx, k)}</div>;
        case 'Card':
            return <Card key={k} style={{ flex: 1 }}>
                <Card.Body>{c.child ? renderNode(c.child, map, ctx, k + ':' + c.child) : null}</Card.Body></Card>;
        case 'Text': {
            const v = c.variant || 'body';
            const txt = String(dyn(ctx, c.text));
            const m = /^h([1-5])$/.exec(v);
            if (m) return <Heading key={k} level={Number(m[1])}>{txt}</Heading>;
            if (v === 'caption') return <Paragraph key={k} style={{ fontSize: 12, color: '#8a8a9a' }}>{txt}</Paragraph>;
            return <Markdown key={k} text={txt} />;
        }
        default:
            return <div key={k}>[{t}]</div>;
    }
}

// ============ Parsing A2UI JSONL ============

function parseA2UI(text) {
    const map = {};
    let dataModel = {};
    let root = null;
    text.split('\n').forEach((line) => {
        line = line.trim();
        if (!line) return;
        let msg;
        try { msg = JSON.parse(line); } catch (e) { return; }
        if (msg.updateComponents) {
            (msg.updateComponents.components || []).forEach((comp) => { map[comp.id] = comp; });
            if (!root && map.root) root = 'root';
        }
        if (msg.updateDataModel) {
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
        if (msg.deleteSurface) { Object.keys(map).forEach((kk) => delete map[kk]); dataModel = {}; root = null; }
    });
    return { map, root, dataModel };
}

// ============ App + montage ============

function App({ src }) {
    const [s, setS] = useState({ status: 'loading' });
    useEffect(() => {
        fetch(src)
            .then((r) => { if (!r.ok) throw new Error('HTTP ' + r.status); return r.text(); })
            .then((text) => { const p = parseA2UI(text); setS({ status: 'ok', ...p, count: Object.keys(p.map).length }); })
            .catch((e) => setS({ status: 'error', error: e.message }));
    }, [src]);

    return (
        <SplunkThemeProvider family="prisma" colorScheme="light" density="comfortable">
            <div style={{ padding: 8 }}>
                {s.status === 'loading' && <Paragraph>Chargement du rapport A2UI…</Paragraph>}
                {s.status === 'error' && (
                    <Paragraph>⚠ A2UI introuvable ({src}) : {s.error}. Génère le snapshot
                        (bin/gen_a2ui.py) ou lance l'agent (bin/a2ui_agent.py).</Paragraph>
                )}
                {s.status === 'ok' && (
                    <div>
                        {s.root && renderNode(s.root, s.map, s.dataModel, s.root)}
                        <Paragraph style={{ color: '#98a2b3', fontSize: 11, marginTop: 12 }}>
                            Rendu via {s.count} composants A2UI → contrôles @splunk/react-ui (protocole Agent-to-UI v0.9).
                        </Paragraph>
                    </div>
                )}
            </div>
        </SplunkThemeProvider>
    );
}

function mountAll() {
    document.querySelectorAll('[data-a2ui-src]').forEach((el) => {
        if (el.getAttribute('data-mounted')) return;
        el.setAttribute('data-mounted', '1');
        ReactDOM.render(<App src={el.getAttribute('data-a2ui-src')} />, el);
    });
}

function pollMount() {
    let n = 0;
    const timer = setInterval(() => {
        if (document.querySelector('[data-a2ui-src]:not([data-mounted])')) mountAll();
        if (++n > 100) clearInterval(timer);
    }, 150);
}

if (typeof window !== 'undefined' && typeof window.require === 'function') {
    try { window.require(['splunkjs/mvc/simplexml/ready!'], () => { mountAll(); pollMount(); }); }
    catch (e) { pollMount(); }
} else { pollMount(); }

export default App;
