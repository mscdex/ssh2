module.exports = {
  readUInt32BE: function readUInt32BE(buf, offset) {
    return buf[offset++] * 16777216
           + buf[offset++] * 65536
           + buf[offset++] * 256
           + buf[offset];
  },
  writeUInt32BE: function writeUInt32BE(buf, value, offset) {
    buf[offset + 3] = value;
    value = value >>> 8;
    buf[offset + 2] = value;
    value = value >>> 8;
    buf[offset + 1] = value;
    value = value >>> 8;
    buf[offset] = value;
    return offset + 4;
  },
  writeUInt32LE: function writeUInt32LE(buf, value, offset) {
    buf[offset++] = value;
    value = value >>> 8;
    buf[offset++] = value;
    value = value >>> 8;
    buf[offset++] = value;
    value = value >>> 8;
    buf[offset++] = value;
    return offset;
  }
};
