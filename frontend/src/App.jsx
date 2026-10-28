import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import ReactFlow, {
  Background,
  Controls,
  Handle,
  Position,
  ReactFlowProvider,
  useReactFlow,
} from 'reactflow';
import 'reactflow/dist/style.css';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import { buildSampleRun } from './sampleRun.js';
import NlpLab from './NlpLab.jsx';

const DX = 300;
const DY = 160;
const GOLD = '#ffd444';
const COLORS = { gold: '#ffd444', warn: '#f5b942', safe: '#4ade80', bad: '#ff5c5c' };

/* ---------- classification helpers ---------- */
function classify(type, boundary, details) {
  const t = String(type || '').toLowerCase();
  const d = details || {};
  if (t.includes('user')) return 'gold';
  if (t.includes('document') || t.includes('retriev')) return 'gold';
  if (t.includes('filter') || t.includes('delimiter') || t.includes('neutraliz')) return 'safe';
  if (t.includes('attacker') || t.includes('payload')) return 'warn';
  if (t.includes('propose') || t.includes('attempt') || t.includes('tool_call')) return 'warn';
  if (t.includes('blocked') || t.includes('deny')) return 'safe';
  if (t.includes('executed')) return d.authorized === false || boundary ? 'bad' : 'gold';
  if (t.includes('boundary') || t.includes('violation') || t.includes('exploit')) return 'bad';
  if (t.includes('response')) return 'gold';
  if (t.includes('oracle') || t.includes('eval')) return boundary ? 'bad' : 'safe';
  if (t.includes('policy') || t.includes('decision')) return 'warn';
  if (t.includes('reason')) return 'gold';
  return 'gold';
}

function outcomeKind(outcome) {
  const o = String(outcome || '').toUpperCase();
  if (o.includes('EXPLOIT')) return 'bad';
  if (o.includes('BLOCK')) return 'warn';
  if (o.includes('DEFEND')) return 'safe';
  if (o.includes('BENIGN')) return 'safe';
  return 'gold';
}

function humanize(type) {
  return String(type || 'event').replace(/[_-]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function summarize(ev) {
  if (ev.message) return ev.message;
  const d = ev.details || {};
  const keys = ['prompt', 'tool', 'control', 'operation', 'channel', 'content', 'reason', 'recipient'];
  const parts = [];
  for (const k of keys) {
    if (d[k] != null && String(d[k]).length) parts.push(`${k}: ${d[k]}`);
    if (parts.length >= 2) break;
  }
  if (d.canary_in_body) parts.unshift('canary leaked');
  if (d.untrusted_instruction_present) parts.push('untrusted content');
  return parts.join(' · ') || '—';
}

/* ---------- custom node ---------- */
function AbNode({ data }) {
  const cls = `node k-${data.kind}${data.active ? ' active' : ''}`;
  const dotColor = COLORS[data.kind] || GOLD;
  return (
    <div className={cls}>
      <Handle type="target" position={Position.Left} style={{ background: GOLD, width: 7, height: 7, border: 'none' }} />
      <div className="ntype">
        <span>{data.badge}</span>
        <span className="badge-dot" style={{ background: dotColor }} />
      </div>
      <div className="ntitle">{data.title}</div>
      {data.sub && <div className="nsub">{data.sub}</div>}
      {data.actor && <div className="actor">{data.actor}</div>}
      <Handle type="source" position={Position.Right} style={{ background: GOLD, width: 7, height: 7, border: 'none' }} />
    </div>
  );
}
const nodeTypes = { abnode: AbNode };

/* ---------- graph builder ---------- */
function buildGraph(traces, rootLabel) {
  const nodes = [];
  const edges = [];
  const n = traces.length || 1;
  const centerY = ((n - 1) / 2) * DY;

  nodes.push({
    id: 'root',
    type: 'abnode',
    position: { x: 0, y: centerY },
    data: { badge: 'START', title: rootLabel, sub: 'Campaign dispatch', actor: 'security tester', kind: 'gold' },
  });

  const addEdge = (s, t, kind) => {
    edges.push({
      id: `${s}->${t}`,
      source: s,
      target: t,
      type: 'default',
      animated: true,
      style: { stroke: kind === 'bad' ? COLORS.bad : GOLD, strokeWidth: 1.7 },
    });
  };

  traces.forEach((tr, i) => {
    const y = i * DY;
    const tc = tr.test_case || {};
    const headerId = `b${i}_h`;
    nodes.push({
      id: headerId,
      type: 'abnode',
      position: { x: DX, y },
      data: {
        badge: tc.owasp_id || 'SCENARIO',
        title: tc.scenario_code || tc.scenario_name || `Scenario ${i + 1}`,
        sub: tc.scenario_name || '',
        actor: 'attacker agent',
        kind: 'warn',
      },
    });
    addEdge('root', headerId);

    let prev = headerId;
    const events = tr.events || [];
    events.forEach((e, j) => {
      const id = `b${i}_e${j}`;
      const kind = classify(e.event_type || e.type, e.boundary_crossed, e.details);
      nodes.push({
        id,
        type: 'abnode',
        position: { x: DX * (2 + j), y },
        data: {
          badge: `STEP ${e.sequence || e.step || j + 1}`,
          title: humanize(e.event_type || e.type),
          sub: summarize(e),
          actor: e.actor || '',
          kind,
        },
      });
      addEdge(prev, id, kind);
      prev = id;
    });

    const outId = `b${i}_out`;
    const ok = outcomeKind(tc.outcome);
    nodes.push({
      id: outId,
      type: 'abnode',
      position: { x: DX * (2 + events.length), y },
      data: {
        badge: 'VERDICT',
        title: (tc.outcome || 'COMPLETED').replace(/_/g, ' '),
        sub: tc.data_leaked ? `leaked: ${(tc.leaked_tokens || []).join(', ')}` : (tc.attack_succeeded ? 'policy violated' : 'no violation'),
        actor: 'security oracle',
        kind: ok,
      },
    });
    addEdge(prev, outId, ok);
  });

  return { nodes, edges };
}

/* ---------- live flow canvas (handles reveal + fit) ---------- */
function FlowCanvas({ allNodes, allEdges, visible }) {
  const rf = useReactFlow();
  const orderIndex = useMemo(() => {
    const m = {};
    allNodes.forEach((n, i) => (m[n.id] = i));
    return m;
  }, [allNodes]);

  const nodes = useMemo(() => {
    return allNodes.slice(0, visible).map((n, i) => ({
      ...n,
      data: { ...n.data, active: i === visible - 1 && visible < allNodes.length },
    }));
  }, [allNodes, visible]);

  const edges = useMemo(() => {
    return allEdges.filter(
      (e) => orderIndex[e.source] < visible && orderIndex[e.target] < visible
    );
  }, [allEdges, orderIndex, visible]);

  useEffect(() => {
    const t = setTimeout(() => rf.fitView({ padding: 0.18, duration: 400 }), 60);
    return () => clearTimeout(t);
  }, [visible, rf]);

  return (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      fitView
      nodesDraggable={false}
      nodesConnectable={false}
      proOptions={{ hideAttribution: true }}
      minZoom={0.15}
    >
      <Background color="#1b1b1f" gap={22} size={1} />
      <Controls showInteractive={false} />
    </ReactFlow>
  );
}

/* ---------- API ---------- */
async function fetchJSON(path, opts) {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try { const b = await res.json(); if (b.detail) msg = b.detail; } catch {}
    throw new Error(msg);
  }
  return res.json();
}

async function runLiveCampaign(executionMode, onStatus) {
  onStatus('Loading target agents…');
  const agents = await fetchJSON('/api/agents');
  const agent =
    agents.find((a) => /vuln|unprot|baseline/i.test(a.id + ' ' + a.name)) || agents[0];
  if (!agent) throw new Error('No agents returned by backend.');

  onStatus('Loading scenario catalog…');
  const scenarios = await fetchJSON('/api/scenarios');
  const codes = scenarios.map((s) => s.code);

  onStatus('Dispatching campaign to target agent…');
  const run = await fetchJSON('/api/test-runs', {
    method: 'POST',
    body: JSON.stringify({
      agent_id: agent.id,
      name: 'Live Flow Run',
      scenario_codes: codes,
      include_benign_baseline: true,
      enable_adaptive_followups: false,
      execution_mode: executionMode,
      max_steps: 16,
      time_budget_seconds: 60,
      llm_config: { provider: 'openrouter' },
    }),
  });

  onStatus('Collecting execution traces…');
  const tr = await fetchJSON(`/api/test-runs/${run.id}/traces`);
  return { run: tr.run || run, traces: tr.traces || [] };
}

async function runLiveSingle(agentMode, onStatus) {
  onStatus('Launching live document scan…');
  const r = await fetchJSON('/api/real/scan', {
    method: 'POST',
    body: JSON.stringify({ agent_mode: agentMode, scenario: 'injection' }),
  });
  const outcome = r.attack_success ? 'EXPLOITED' : 'DEFENDED_SAFE';
  const sev = (r.finding && r.finding.severity) || (r.attack_success ? 'High' : 'Low');
  const capSev = sev.charAt(0).toUpperCase() + sev.slice(1);
  const leaked = r.metrics && r.metrics.canary_exposed;
  const run = {
    id: r.run_id,
    agent_name: r.model || 'Live LLM target',
    metrics_summary: {
      total_test_cases: 1,
      completed_adversarial_tests: 1,
      completed_benign_tests: 0,
      confirmed_vulnerabilities: r.attack_success ? 1 : 0,
      successful_attacks: r.attack_success ? 1 : 0,
      defended_or_blocked_attacks: r.attack_success ? 0 : 1,
      attack_success_rate: r.attack_success ? 100 : 0,
      sensitive_data_leakage_rate: leaked ? 100 : 0,
      benign_task_success_rate: 100,
      test_coverage_rate: 100,
      reproducibility_rate: 100,
      severity_distribution: r.attack_success ? { [capSev]: 1, Critical: 0, High: 0, Medium: 0, Low: 0 } : { Critical: 0, High: 0, Medium: 0, Low: 0 },
      category_breakdown: [
        { category: 'Prompt Injection', successful_attacks: r.attack_success ? 1 : 0, blocked_or_safe: r.attack_success ? 0 : 1 },
      ],
    },
  };
  const traces = [
    {
      test_case: {
        scenario_code: 'LIVE-SCAN',
        scenario_name: 'Live Document Scan (injection)',
        owasp_id: 'LLM01',
        outcome,
        attack_succeeded: r.attack_success,
        data_leaked: !!leaked,
        leaked_tokens: leaked ? ['CANARY'] : [],
      },
      events: r.events || [],
    },
  ];
  return { run, traces };
}

/* ---------- metrics section ---------- */
function Metrics({ run, traces }) {
  if (!run) return null;
  const m = run.metrics_summary || {};

  const outcomeCounts = {};
  traces.forEach((t) => {
    const o = (t.test_case.outcome || 'OTHER').replace(/_/g, ' ');
    outcomeCounts[o] = (outcomeCounts[o] || 0) + 1;
  });
  const outcomeData = Object.entries(outcomeCounts).map(([name, value]) => ({
    name,
    value,
    fill: outcomeKind(name) === 'bad' ? COLORS.bad : outcomeKind(name) === 'safe' ? COLORS.safe : outcomeKind(name) === 'warn' ? COLORS.warn : GOLD,
  }));

  const sev = m.severity_distribution || {};
  const sevData = [
    { name: 'Critical', value: sev.Critical || 0, fill: GOLD },
    { name: 'High', value: sev.High || 0, fill: '#e2b93b' },
    { name: 'Medium', value: sev.Medium || 0, fill: '#8a7020' },
    { name: 'Low', value: sev.Low || 0, fill: '#3f3f46' },
  ].filter((d) => d.value > 0);

  const cat = (m.category_breakdown || []).map((c) => ({
    category: c.category,
    Exploited: c.successful_attacks || 0,
    'Blocked/Safe': c.blocked_or_safe || 0,
  }));

  const tip = { backgroundColor: '#0d0d0f', border: `1px solid ${GOLD}`, borderRadius: 10, color: '#fff', fontSize: 12 };
  const nlp = m.nlp_engine;

  return (
    <>
      <div className="section-title font-serif">Live Metrics</div>
      <div className="section-sub font-cursive">Computed from this run's deterministic oracle verdicts</div>

      <div className="kpis">
        <div className="card kpi"><div className="label">Attack Success Rate</div><div className="value bad">{m.attack_success_rate ?? 0}%</div></div>
        <div className="card kpi"><div className="label">Confirmed Vulnerabilities</div><div className="value gold">{m.confirmed_vulnerabilities ?? 0}</div></div>
        <div className="card kpi"><div className="label">Data Leakage Rate</div><div className="value bad">{m.sensitive_data_leakage_rate ?? 0}%</div></div>
        <div className="card kpi"><div className="label">Benign Task Success</div><div className="value safe">{m.benign_task_success_rate ?? 0}%</div></div>
        <div className="card kpi"><div className="label">Reproducibility</div><div className="value gold">{m.reproducibility_rate ?? 0}%</div></div>
      </div>

      {nlp && nlp.enabled && (
        <>
          <div className="section-sub font-cursive" style={{ marginTop: 18 }}>
            NLP engine — language-model detection layer over the deterministic oracle
          </div>
          <div className="kpis">
            <div className="card kpi"><div className="label">NLP Injection Detection</div><div className="value gold">{nlp.injection_detection_rate ?? 0}%</div></div>
            <div className="card kpi"><div className="label">Attacks Flagged by NLP</div><div className="value gold">{nlp.attacks_flagged_by_nlp ?? 0}</div></div>
            <div className="card kpi"><div className="label">Suspected Semantic Leaks</div><div className="value bad">{nlp.suspected_semantic_leaks ?? 0}</div></div>
            <div className="card kpi"><div className="label">Refusals Detected</div><div className="value safe">{nlp.refusals_detected ?? 0}</div></div>
            <div className="card kpi"><div className="label">False-Positive Rate</div><div className="value gold">{m.false_positive_rate ?? 0}%</div></div>
          </div>
        </>
      )}

      <div className="charts">
        <div className="card chartcard">
          <h3>Outcome Distribution</h3>
          <div style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={outcomeData} margin={{ top: 8, right: 12, left: -16, bottom: 28 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e1e22" />
                <XAxis dataKey="name" stroke="#a1a1aa" tick={{ fill: '#fff', fontSize: 10 }} angle={-12} textAnchor="end" height={48} />
                <YAxis stroke="#a1a1aa" tick={{ fill: '#fff', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={tip} cursor={{ fill: 'rgba(255,212,68,0.06)' }} />
                <Bar dataKey="value" name="Test cases" radius={[4, 4, 0, 0]}>
                  {outcomeData.map((e, i) => <Cell key={i} fill={e.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card chartcard">
          <h3>Vulnerabilities by Category</h3>
          <div style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={cat} margin={{ top: 8, right: 12, left: -16, bottom: 28 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e1e22" />
                <XAxis dataKey="category" stroke="#a1a1aa" tick={{ fill: '#fff', fontSize: 10 }} angle={-12} textAnchor="end" height={48} />
                <YAxis stroke="#a1a1aa" tick={{ fill: '#fff', fontSize: 11 }} allowDecimals={false} />
                <Tooltip contentStyle={tip} cursor={{ fill: 'rgba(255,212,68,0.06)' }} />
                <Legend wrapperStyle={{ color: '#fff', fontSize: 11 }} />
                <Bar dataKey="Exploited" fill={COLORS.bad} radius={[4, 4, 0, 0]} />
                <Bar dataKey="Blocked/Safe" fill={COLORS.safe} radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {sevData.length > 0 && (
          <div className="card chartcard">
            <h3>Severity Distribution</h3>
            <div style={{ height: 260 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={sevData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={88} label={{ fill: '#fff', fontSize: 11 }}>
                    {sevData.map((e, i) => <Cell key={i} fill={e.fill} />)}
                  </Pie>
                  <Tooltip contentStyle={tip} />
                  <Legend wrapperStyle={{ color: '#fff', fontSize: 11 }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        <div className="card chartcard">
          <h3>Campaign Coverage</h3>
          <div style={{ padding: '6px 2px' }}>
            <Row label="Total test cases" value={m.total_test_cases ?? traces.length} />
            <Row label="Adversarial tests" value={m.completed_adversarial_tests ?? '—'} />
            <Row label="Benign baseline tests" value={m.completed_benign_tests ?? '—'} />
            <Row label="Scenario coverage" value={`${m.test_coverage_rate ?? 0}%`} />
            <Row label="Target" value={run.agent_name || '—'} mono />
          </div>
        </div>
      </div>
    </>
  );
}

function Row({ label, value, mono }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 2px', borderBottom: '1px solid #17171a', fontSize: 13 }}>
      <span style={{ color: '#a1a1aa' }}>{label}</span>
      <span className={mono ? 'font-mono' : ''} style={{ color: '#fff', fontWeight: 600 }}>{value}</span>
    </div>
  );
}

/* ---------- app ---------- */
export default function App() {
  const [view, setView] = useState('flow'); // flow | nlp
  const [mode, setMode] = useState('campaign'); // campaign | single | simulated
  const [execMode, setExecMode] = useState('deterministic');
  const [speed, setSpeed] = useState(550);
  const [status, setStatus] = useState({ text: 'Idle — choose a mode and press Run.', state: 'idle' });
  const [data, setData] = useState(null); // {run, traces}
  const [graph, setGraph] = useState({ nodes: [], edges: [] });
  const [visible, setVisible] = useState(0);
  const [running, setRunning] = useState(false);
  const timer = useRef(null);

  const clearTimer = () => { if (timer.current) { clearInterval(timer.current); timer.current = null; } };
  useEffect(() => () => clearTimer(), []);

  const startReveal = useCallback((g) => {
    clearTimer();
    setVisible(0);
    let k = 0;
    timer.current = setInterval(() => {
      k += 1;
      setVisible(k);
      if (k >= g.nodes.length) {
        clearTimer();
        setStatus({ text: `Flow complete — ${g.nodes.length} steps across ${data ? '' : ''}the campaign.`, state: 'done' });
      }
    }, speed);
  }, [speed, data]);

  const run = useCallback(async () => {
    setRunning(true);
    setData(null);
    setGraph({ nodes: [], edges: [] });
    setVisible(0);
    setStatus({ text: 'Starting…', state: 'running' });
    try {
      let result;
      const rootLabel = mode === 'single' ? 'Live Document Scan' : 'Target Agent';
      if (mode === 'simulated') {
        setStatus({ text: 'Running simulated campaign…', state: 'running' });
        result = buildSampleRun();
      } else if (mode === 'single') {
        result = await runLiveSingle('vulnerable', (t) => setStatus({ text: t, state: 'running' }));
      } else {
        result = await runLiveCampaign(execMode, (t) => setStatus({ text: t, state: 'running' }));
      }
      setData(result);
      const g = buildGraph(result.traces, rootLabel);
      setGraph(g);
      setStatus({ text: 'Agents processing — building live flow…', state: 'running' });
      startReveal(g);
    } catch (err) {
      setStatus({ text: `Backend error: ${err.message}. Tip: start the backend on :8000, or use Simulated mode.`, state: 'error' });
    } finally {
      setRunning(false);
    }
  }, [mode, execMode, startReveal]);

  const flowDone = graph.nodes.length > 0 && visible >= graph.nodes.length;

  return (
    <div className="app">
      <div className="viewnav">
        <button className={`viewtab ${view === 'flow' ? 'on' : ''}`} onClick={() => setView('flow')}>Live Agent Flow</button>
        <button className={`viewtab ${view === 'nlp' ? 'on' : ''}`} onClick={() => setView('nlp')}>NLP Security Lab</button>
      </div>

      {view === 'nlp' && <NlpLab />}
      {view === 'flow' && (
      <>
      <div className="header">
        <div className="brandtag">AGENTBREAK / LIVE</div>
        <h1 className="font-serif">Autonomous Agent Flow</h1>
        <div className="subtitle font-cursive">Watch the agents attack, execute, and get judged — step by step, in real time.</div>
      </div>

      <div className="card controls">
        <div className="field">
          <label>Mode</label>
          <select value={mode} onChange={(e) => setMode(e.target.value)}>
            <option value="campaign">Live Campaign (all scenarios)</option>
            <option value="single">Live Single Scan</option>
            <option value="simulated">Simulated (no backend)</option>
          </select>
        </div>
        {mode === 'campaign' && (
          <div className="field">
            <label>Execution</label>
            <select value={execMode} onChange={(e) => setExecMode(e.target.value)}>
              <option value="deterministic">Deterministic (no API key)</option>
              <option value="hybrid_llm">Hybrid LLM (OpenRouter)</option>
            </select>
          </div>
        )}
        <div className="field">
          <label>Reveal speed</label>
          <select value={speed} onChange={(e) => setSpeed(Number(e.target.value))}>
            <option value={900}>Slow</option>
            <option value={550}>Normal</option>
            <option value={250}>Fast</option>
          </select>
        </div>
        <button className="btn" onClick={run} disabled={running}>
          {running ? 'Running…' : 'Run'}
        </button>
      </div>

      <div className={`statusbar ${status.state}`}>
        <span className="dot" />
        <span>{status.text}</span>
      </div>

      <div className="flowwrap">
        <ReactFlowProvider>
          <FlowCanvas allNodes={graph.nodes} allEdges={graph.edges} visible={visible} />
        </ReactFlowProvider>
      </div>

      <div className="legend">
        <span><span className="badge-dot" style={{ background: COLORS.gold }} /> Input / Action</span>
        <span><span className="badge-dot" style={{ background: COLORS.warn }} /> Attack attempt</span>
        <span><span className="badge-dot" style={{ background: COLORS.safe }} /> Blocked / Safe</span>
        <span><span className="badge-dot" style={{ background: COLORS.bad }} /> Breach / Exploited</span>
      </div>

      {flowDone && <Metrics run={data.run} traces={data.traces} />}
      </>
      )}
    </div>
  );
}
