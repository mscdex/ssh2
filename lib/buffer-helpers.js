module.exports = {
  readUInt32BE: function readUInt32BE(buf, offset) {
    return buf[offset++] * 16777216
           + buf[offset++] * 65536
           + buf[offset++] * 256
           + buf[offset];
  },
  writeUInt32BE: function writeUInt32BE(buf, value, offset) {
    buf[offset++] = (value >>> 24);
    buf[offset++] = (value >>> 16);
    buf[offset++] = (value >>> 8);
    buf[offset++] = value;
    return offset;
  },
  writeUInt32LE: function writeUInt32LE(buf, value, offset) {
    buf[offset++] = value;
    buf[offset++] = (value >>> 8);
    buf[offset++] = (value >>> 16);
    buf[offset++] = (value >>> 24);
    return offset;
  }
};
