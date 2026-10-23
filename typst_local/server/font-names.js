// Reads the family names a font file declares, so "unknown font family"
// messages can say which names the available fonts actually provide.

/** Returns the family names in a TrueType/OpenType font (first face of a collection). */
export function fontFamilies(buf) {
  try {
    let offset = 0;
    if (buf.toString('latin1', 0, 4) === 'ttcf') offset = buf.readUInt32BE(12);
    const numTables = buf.readUInt16BE(offset + 4);
    let name = null;
    for (let i = 0; i < numTables; i++) {
      const rec = offset + 12 + i * 16;
      if (buf.toString('latin1', rec, rec + 4) === 'name') name = buf.readUInt32BE(rec + 8);
    }
    if (name === null) return [];
    const count = buf.readUInt16BE(name + 2);
    const strings = name + buf.readUInt16BE(name + 4);
    const found = { 1: new Set(), 16: new Set() };
    for (let i = 0; i < count; i++) {
      const rec = name + 6 + i * 12;
      const platform = buf.readUInt16BE(rec);
      const nameId = buf.readUInt16BE(rec + 6);
      if (nameId !== 1 && nameId !== 16) continue;
      const len = buf.readUInt16BE(rec + 8);
      const start = strings + buf.readUInt16BE(rec + 10);
      const raw = buf.subarray(start, start + len);
      // Windows/Unicode names are UTF-16BE; Mac names are (roughly) Latin-1.
      const text = platform === 1 ? raw.toString('latin1') : Buffer.from(raw).swap16().toString('utf16le');
      if (text.trim()) found[nameId].add(text.trim());
    }
    // Typst prefers the typographic family (16) and falls back to the legacy one (1).
    return [...(found[16].size ? found[16] : found[1])];
  } catch {
    return [];
  }
}

/**
 * What Word needs to embed a font: its legacy family name (name ID 1, which
 * Word matches on), whether it's bold/italic, whether it has TrueType outlines
 * (the kind Word embeds), and whether its licence allows embedding.
 */
export function fontFaceInfo(buf) {
  try {
    let offset = 0;
    if (buf.toString('latin1', 0, 4) === 'ttcf') offset = buf.readUInt32BE(12);
    const numTables = buf.readUInt16BE(offset + 4);
    const tables = {};
    for (let i = 0; i < numTables; i++) {
      const rec = offset + 12 + i * 16;
      tables[buf.toString('latin1', rec, rec + 4)] = buf.readUInt32BE(rec + 8);
    }
    let family = null;
    if (tables.name !== undefined) {
      const name = tables.name;
      const count = buf.readUInt16BE(name + 2);
      const strings = name + buf.readUInt16BE(name + 4);
      for (let i = 0; i < count && !family; i++) {
        const rec = name + 6 + i * 12;
        if (buf.readUInt16BE(rec + 6) !== 1 || buf.readUInt16BE(rec) !== 3) continue;
        const raw = buf.subarray(strings + buf.readUInt16BE(rec + 10), strings + buf.readUInt16BE(rec + 10) + buf.readUInt16BE(rec + 8));
        family = Buffer.from(raw).swap16().toString('utf16le').trim();
      }
    }
    let weight = 400;
    let italic = false;
    let embeddable = true;
    if (tables['OS/2'] !== undefined) {
      const os2 = tables['OS/2'];
      const fsType = buf.readUInt16BE(os2 + 8);
      embeddable = (fsType & 0x0002) === 0; // "restricted license" forbids embedding
      weight = buf.readUInt16BE(os2 + 4);
      italic = (buf.readUInt16BE(os2 + 62) & 0x0001) !== 0;
    }
    return { family, weight, italic, trueType: tables.glyf !== undefined, embeddable };
  } catch {
    return null;
  }
}
