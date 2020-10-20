'use strict';

const {
  SSHTTPAgent: HTTPAgent,
  SSHTTPSAgent: HTTPSAgent,
} = require('./http-agents.js');
const { parseKey } = require('./protocol/keyParser.js');
const {
  flagsToString,
  OPEN_MODE,
  STATUS_CODE,
  stringToFlags,
} = require('./protocol/SFTP.js');

module.exports = {
  Client: require('./client.js'),
  HTTPAgent,
  HTTPSAgent,
  Server: require('./server.js'),
  utils: {
    parseKey,
    sftp: {
      flagsToString,
      OPEN_MODE,
      STATUS_CODE,
      stringToFlags,
    },
  },
};
