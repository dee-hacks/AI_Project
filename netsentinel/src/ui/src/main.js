/**
 * NetSentinel UI — Main entry point.
 * Initializes D3.js components, WebSocket, and event handlers.
 */
import * as d3 from 'd3';
import { createWebSocket } from './hooks/useWebSocket.js';
import { createTopologyFetcher } from './hooks/useTopology.js';
import { renderGraph, renderTimeline } from './utils/d3Layout.js';
import { getState, addAlert, updateTopology, updateStats, setConnectionStatus, subscribe } from './store/store.js';

// ─── DOM References ───────────────────────────────────────────
const topologySvg = document.getElementById('topology-svg');
const timelineSvg = document.getElementById('timeline-svg');
const alertBody = document.getElementById('alert-body');
const statTotal = document.getElementById('stat-total');
const statCritical = document.getElementById('stat-critical');
const statHigh = document.getElementById('stat-high');
const dashTotal = document.getElementById('dash-total');
const dashActive = document.getElementById('dash-active');
const dashNodes = document.getElementById('dash-nodes');
const filterSeverity = document.getElementById('filter-severity');
const filterIp = document.getElementById('filter-ip');
const btnRefresh = document.getElementById('btn-refresh');

let topologySimulation = null;
let eventBuffer = [];

// ─── WebSocket ────────────────────────────────────────────────
const ws = createWebSocket(
  `ws://${window.location.host}/ws/v1/alerts`,
  (data) => {
    if (data.type === 'alert' && data.data) {
      const alerts = Array.isArray(data.data) ? data.data : [data.data];
      alerts.forEach((alert) => {
        addAlert(alert);
        eventBuffer.push(alert);
      });
      renderAlerts();
      renderTimeline(timelineSvg, eventBuffer.slice(-100));
      updateHeaderStats();
    }
  },
  (connected) => {
    setConnectionStatus(connected);
  }
);

ws.connect();

// ─── Topology ─────────────────────────────────────────────────
const topologyFetcher = createTopologyFetcher((data) => {
  updateTopology(data);
  topologySimulation = renderGraph(topologySvg, data);
}, 15000);

topologyFetcher.start();

// ─── Stats Polling ────────────────────────────────────────────
async function fetchStats() {
  try {
    const [summaryRes, nodesRes] = await Promise.all([
      fetch('/api/v1/events/stats/summary'),
      fetch('/api/v1/topology/nodes'),
    ]);

    const summary = await summaryRes.json();
    const nodes = await nodesRes.json();

    updateStats({
      total: summary.total || 0,
      high: summary.high || 0,
      critical: summary.critical || 0,
      active: summary.recent_5min || 0,
      nodes: nodes.count || 0,
    });

    updateHeaderStats();
    updateDashboardStats();
  } catch (e) {
    console.warn('Stats fetch failed:', e);
  }
}

fetchStats();
setInterval(fetchStats, 30000);

// ─── Alert Fetching ───────────────────────────────────────────
async function fetchAlerts() {
  try {
    const severity = filterSeverity.value.trim() || undefined;
    const srcIp = filterIp.value.trim() || undefined;

    let url = '/api/v1/alerts?limit=100';
    if (severity) url += `&severity=${severity}`;

    const response = await fetch(url);
    const data = await response.json();
    const alerts = data.alerts || [];

    // Replace global state
    getState().alerts = alerts;
    eventBuffer = alerts.slice(0, 100);
    renderAlerts();
    renderTimeline(timelineSvg, eventBuffer);
  } catch (e) {
    console.warn('Alert fetch failed:', e);
  }
}

fetchAlerts();

// ─── Rendering ────────────────────────────────────────────────
function renderAlerts() {
  const alerts = getState().alerts;
  const severityFilter = filterSeverity.value.trim().toLowerCase();
  const ipFilter = filterIp.value.trim().toLowerCase();

  let filtered = alerts;
  if (severityFilter) {
    filtered = filtered.filter((a) => a.severity?.toLowerCase() === severityFilter);
  }
  if (ipFilter) {
    filtered = filtered.filter(
      (a) =>
        (a.src_ip && a.src_ip.includes(ipFilter)) ||
        (a.dst_ip && a.dst_ip.includes(ipFilter))
    );
  }

  if (filtered.length === 0) {
    alertBody.innerHTML = '<tr><td colspan="7">No alerts found.</td></tr>';
    return;
  }

  alertBody.innerHTML = filtered.slice(0, 100).map((alert) => {
    const time = alert.timestamp
      ? new Date(alert.timestamp * 1000).toLocaleTimeString()
      : '-';
    const severity = alert.severity || 'unknown';
    return `
      <tr>
        <td>${time}</td>
        <td><span class="badge badge-${severity}">${severity}</span></td>
        <td>${alert.src_ip || '-'}:${alert.sport || '-'}</td>
        <td>${alert.dst_ip || '-'}:${alert.dport || '-'}</td>
        <td>${fmtProtocol(alert.protocol)}</td>
        <td>${alert.anomaly_score?.toFixed(4) || '-'}</td>
        <td>${alert.status || 'open'}</td>
      </tr>
    `;
  }).join('');
}

function updateHeaderStats() {
  const alerts = getState().alerts;
  const total = alerts.length;
  const critical = alerts.filter((a) => a.severity === 'critical').length;
  const high = alerts.filter((a) => a.severity === 'high').length;

  statTotal.textContent = total;
  statCritical.textContent = critical;
  statHigh.textContent = high;
}

function updateDashboardStats() {
  const stats = getState().stats;
  dashTotal.textContent = stats.total || 0;
  dashActive.textContent = stats.active || 0;
  dashNodes.textContent = stats.nodes || 0;
}

function fmtProtocol(proto) {
  const map = { 6: 'TCP', 17: 'UDP', 1: 'ICMP' };
  return map[proto] || `Proto-${proto}`;
}

// ─── Event Handlers ───────────────────────────────────────────
filterSeverity.addEventListener('input', renderAlerts);
filterIp.addEventListener('input', renderAlerts);

btnRefresh.addEventListener('click', () => {
  fetchAlerts();
  fetchStats();
  topologyFetcher.refresh();
});

// Resize handling
window.addEventListener('resize', () => {
  if (topologySimulation) {
    const width = topologySvg.clientWidth;
    const height = topologySvg.clientHeight;
    topologySimulation.force('center', d3.forceCenter(width / 2, height / 2));
    topologySimulation.alpha(0.3).restart();
  }
});

// ─── Initial Render ───────────────────────────────────────────
renderTimeline(timelineSvg, []);

console.log('NetSentinel UI initialized');