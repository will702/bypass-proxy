import { connect } from 'cloudflare:sockets';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/' || url.pathname === '/health') {
      return new Response(JSON.stringify({
        status: 'online',
        service: 'bypass-relay',
        version: '1.0.0'
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // WebSocket TCP Tunnel
    if (url.pathname === '/tunnel') {
      const upgradeHeader = request.headers.get('Upgrade');
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        return new Response('Expected WebSocket upgrade', { status: 426 });
      }

      const target = url.searchParams.get('target');
      if (!target) {
        return new Response('Missing target parameter (host:port)', { status: 400 });
      }

      let [hostname, portStr] = target.split(':');
      let port = parseInt(portStr || '443', 10);
      if (isNaN(port) || port <= 0 || port > 65535) {
        port = 443;
      }

      const webSocketPair = new WebSocketPair();
      const [client, server] = Object.values(webSocketPair);
      server.accept();

      let tcpSocket;
      try {
        tcpSocket = connect({ hostname, port });
      } catch (err) {
        server.close(1011, `TCP connection failed: ${err.message}`);
        return new Response(null, { status: 101, webSocket: client });
      }

      const tcpWriter = tcpSocket.writable.getWriter();
      const tcpReader = tcpSocket.readable.getReader();

      // Pipe WebSocket -> TCP Socket
      server.addEventListener('message', async (event) => {
        try {
          let data;
          if (event.data instanceof ArrayBuffer) {
            data = new Uint8Array(event.data);
          } else if (typeof event.data === 'string') {
            data = new TextEncoder().encode(event.data);
          } else {
            data = new Uint8Array(await event.data.arrayBuffer());
          }
          await tcpWriter.write(data);
        } catch (e) {
          try { server.close(1011, 'TCP write failed'); } catch (_) {}
        }
      });

      server.addEventListener('close', async () => {
        try { await tcpWriter.close(); } catch (_) {}
      });

      server.addEventListener('error', async () => {
        try { await tcpWriter.abort(); } catch (_) {}
      });

      // Pipe TCP Socket -> WebSocket
      (async () => {
        try {
          while (true) {
            const { value, done } = await tcpReader.read();
            if (done) break;
            if (value && value.length > 0) {
              server.send(value);
            }
          }
        } catch (e) {
        } finally {
          try { server.close(1000, 'Stream finished'); } catch (_) {}
        }
      })();

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};
