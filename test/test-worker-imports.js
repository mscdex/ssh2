// Test for thread-safety issues caused by subsequent imports of the module
// in worker threads: https://github.com/mscdex/ssh2/issues/1393.
// Each subsequent worker increases probability of abnormal termination.
// The probability of a false pass due to zero response becomes negligible
// for 4 consecutive workers.
'use strict';

const { Worker, isMainThread } = require('worker_threads');
require('../lib/index.js');

if (isMainThread) {
  async function runWorker() {
    return new Promise((r) => new Worker(__filename).on("exit", r));
  }
  runWorker()
    .then(runWorker)
    .then(runWorker)
    .then(runWorker);
}
