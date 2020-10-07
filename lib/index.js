'use strict';

const HTTPAgents = require('./http-agents.js');
const { parseKey } = require('./protocol/keyParser.js');
const {
  flagsToString,
  OPEN_MODE,
  STATUS_CODE,
  stringToFlags,
} = require('./protocol/SFTP.js');

module.exports = {
  Client: require('./client.js'),
  HTTPAgent: HTTPAgents.SSHTTPAgent,
  HTTPSAgent: HTTPAgents.SSHTTPSAgent,
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
