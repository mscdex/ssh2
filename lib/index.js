'use strict';

const {
  AgentProtocol,
  BaseAgent,
  createAgent,
  CygwinAgent,
  OpenSSHAgent,
  PageantAgent,
} = require('./agent.js');
const {
  SSHTTPAgent: HTTPAgent,
  SSHTTPSAgent: HTTPSAgent,
} = require('./http-agents.js');

module.exports = {
  AgentProtocol,
  BaseAgent,
  createAgent,
  Client: require('./client.js'),
  CygwinAgent,
  HTTPAgent,
  HTTPSAgent,
  OpenSSHAgent,
  PageantAgent,
  Server: require('./server.js'),
  utils: {
    parseKey: require('./protocol/keyParser.js').parseKey,
    sftp: require('./protocol/SFTP.js'),
  },
};
