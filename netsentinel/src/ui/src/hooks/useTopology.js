/**
 * Fetch + polling hook for network topology data.
 */
export function createTopologyFetcher(onUpdate, intervalMs = 10000) {
  let timer = null;
  let abortController = null;

  async function fetchTopology() {
    abortController = new AbortController();
    try {
      const response = await fetch('/api/v1/topology', {
        signal: abortController.signal,
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (onUpdate) onUpdate(data);
    } catch (e) {
      if (e.name !== 'AbortError') {
        console.warn('Topology fetch failed:', e);
      }
    }
  }

  function start() {
    fetchTopology();
    timer = setInterval(fetchTopology, intervalMs);
  }

  function stop() {
    if (timer) {
      clearInterval(timer);
      timer = null;
    }
    if (abortController) {
      abortController.abort();
      abortController = null;
    }
  }

  return { start, stop, refresh: fetchTopology };
}