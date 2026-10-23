// Websocket provider speaking the standard Yjs sync + awareness protocol, plus
// JSON text frames for server events (compile results, project metadata).
import * as Y from 'yjs';
import * as syncProtocol from 'y-protocols/sync';
import * as awarenessProtocol from 'y-protocols/awareness';
import * as encoding from 'lib0/encoding';
import * as decoding from 'lib0/decoding';

const MSG_SYNC = 0;
const MSG_AWARENESS = 1;

export class Provider extends EventTarget {
  /**
   * @param {string} url
   * @param {Y.Doc} doc
   * @param {awarenessProtocol.Awareness} awareness
   */
  constructor(url, doc, awareness) {
    super();
    this.url = url;
    this.doc = doc;
    this.awareness = awareness;
    this.ws = null;
    this.status = 'connecting';
    this.synced = false;
    this.retries = 0;
    this.closed = false;

    doc.on('update', (update, origin) => {
      if (origin === this) return;
      const enc = encoding.createEncoder();
      encoding.writeVarUint(enc, MSG_SYNC);
      syncProtocol.writeUpdate(enc, update);
      this.send(encoding.toUint8Array(enc));
    });

    awareness.on('update', ({ added, updated, removed }, origin) => {
      if (origin === this) return;
      const changed = added.concat(updated, removed);
      const enc = encoding.createEncoder();
      encoding.writeVarUint(enc, MSG_AWARENESS);
      encoding.writeVarUint8Array(enc, awarenessProtocol.encodeAwarenessUpdate(awareness, changed));
      this.send(encoding.toUint8Array(enc));
    });

    window.addEventListener('pagehide', () => {
      awarenessProtocol.removeAwarenessStates(awareness, [doc.clientID], 'window unload');
    });

    this.connect();
  }

  emit(type, detail) {
    this.dispatchEvent(new CustomEvent(type, { detail }));
  }

  setStatus(status) {
    if (this.status === status) return;
    this.status = status;
    this.emit('status', status);
  }

  send(data) {
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(data);
  }

  connect() {
    const ws = (this.ws = new WebSocket(this.url));
    ws.binaryType = 'arraybuffer';
    this.setStatus('connecting');

    ws.onopen = () => {
      this.retries = 0;
      this.setStatus('connected');
      const enc = encoding.createEncoder();
      encoding.writeVarUint(enc, MSG_SYNC);
      syncProtocol.writeSyncStep1(enc, this.doc);
      ws.send(encoding.toUint8Array(enc));
      if (this.awareness.getLocalState() !== null) {
        const aw = encoding.createEncoder();
        encoding.writeVarUint(aw, MSG_AWARENESS);
        encoding.writeVarUint8Array(aw, awarenessProtocol.encodeAwarenessUpdate(this.awareness, [this.doc.clientID]));
        ws.send(encoding.toUint8Array(aw));
      }
    };

    ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        const msg = JSON.parse(event.data);
        this.emit('message', msg);
        return;
      }
      const dec = decoding.createDecoder(new Uint8Array(event.data));
      const type = decoding.readVarUint(dec);
      if (type === MSG_SYNC) {
        const enc = encoding.createEncoder();
        encoding.writeVarUint(enc, MSG_SYNC);
        const syncType = syncProtocol.readSyncMessage(dec, enc, this.doc, this);
        if (encoding.length(enc) > 1) ws.send(encoding.toUint8Array(enc));
        if (syncType === syncProtocol.messageYjsSyncStep2 && !this.synced) {
          this.synced = true;
          this.emit('synced');
        }
      } else if (type === MSG_AWARENESS) {
        awarenessProtocol.applyAwarenessUpdate(this.awareness, decoding.readVarUint8Array(dec), this);
      }
    };

    ws.onclose = (event) => {
      this.ws = null;
      // Forget everyone else; they will be re-announced after reconnecting.
      const others = [...this.awareness.getStates().keys()].filter((id) => id !== this.doc.clientID);
      awarenessProtocol.removeAwarenessStates(this.awareness, others, this);
      if (event.code === 4000) {
        this.closed = true;
        this.setStatus('removed');
        return;
      }
      this.setStatus('disconnected');
      if (this.closed) return;
      const delay = Math.min(10_000, 500 * 2 ** this.retries++);
      setTimeout(() => this.connect(), delay);
    };
  }
}
