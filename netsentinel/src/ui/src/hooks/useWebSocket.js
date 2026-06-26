/**
 * Reconnecting WebSocket for real-time alert streaming.
 */
export function createWebSocket(url, onMessage, onStatusChange) {
  let ws = null;
  let reconnectTimer = null;
  let isConnected = false;

  function connect() {
    if (ws && ws.readyState === WebSocket.OPEN) return;

    try {
      ws = new WebSocket(url);
    } catch (e) {
      console.error('WebSocket connection failed:', e);
      scheduleReconnect();
      return;
    }

    ws.onopen = () => {
      isConnected = true;
      if (onStatusChange) onStatusChange(true);
      clearTimeout(reconnectTimer);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
          return;
        }
        if (onMessage) onMessage(data);
      } catch (e) {
        console.warn('WebSocket parse error:', e);
      }
    };

    ws.onclose = () => {
      isConnected = false;
      if (onStatusChange) onStatusChange(false);
      scheduleReconnect();
    };

    ws.onerror = () => {
      ws.close();
    };
  }

  function scheduleReconnect() {
    clearTimeout(reconnectTimer);
    reconnectTimer = setTimeout(connect, 3000);
  }

  function disconnect() {
    clearTimeout(reconnectTimer);
    if (ws) {
      ws.onclose = null;
      ws.close();
      ws = null;
    }
    isConnected = false;
  }

  function send(data) {
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(data));
    }
  }

  return { connect, disconnect, send, get connected() { return isConnected; } };
}