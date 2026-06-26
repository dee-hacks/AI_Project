/**
 * Simple reactive state store (similar to Zustand pattern).
 * Manages global application state for alerts, topology, and dashboard stats.
 */
const subscribers = new Map();

const state = {
  alerts: [],
  topology: { nodes: [], links: [] },
  stats: { total: 0, high: 0, critical: 0, active: 0, nodes: 0 },
  wsConnected: false,
  lastUpdate: null,
};

export function getState() {
  return state;
}

export function setState(key, value) {
  state[key] = value;
  state.lastUpdate = Date.now();
  notify(key);
}

export function subscribe(key, callback) {
  if (!subscribers.has(key)) {
    subscribers.set(key, new Set());
  }
  subscribers.get(key).add(callback);
  return () => subscribers.get(key).delete(callback);
}

function notify(key) {
  const subs = subscribers.get(key);
  if (subs) {
    subs.forEach((cb) => cb(state[key], state));
  }
}

// Convenience actions
export function addAlert(alert) {
  state.alerts.unshift(alert);
  if (state.alerts.length > 500) state.alerts.pop();
  notify('alerts');
}

export function updateTopology(data) {
  setState('topology', data);
}

export function updateStats(stats) {
  setState('stats', stats);
}

export function setConnectionStatus(connected) {
  setState('wsConnected', connected);
}