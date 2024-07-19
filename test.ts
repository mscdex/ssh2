import { createTestUrlFileSource } from "./urlSource";
import { Agent, request } from 'node:https';
import { Client } from './lib/index';
import { createTestUrlFileDestination } from "./urlDestination";

async function main() {
    const httpsAgent = new Agent({ keepAlive: true, maxSockets: 100 });
    const agent = {
      get(url: string, options: { headers: Record<string, string> }) {
        return request(url, {
          method: 'GET',
          headers: options.headers,
          agent: httpsAgent
        });
      }, 
      put(url: string, options: { headers: Record<string, string> }) {
        return request(url, {
          method: 'PUT',
          headers: options.headers,
          agent: httpsAgent,
        })
      }
    };
    // const objectStorageSource = await createTestUrlFileSource(
    //   agent,
    //   'https://storage.googleapis.com/will-gcs-test-bucket/gcs-file-source/numbers.txt?x-goog-signature=70ff63101c2553696fa0f86dff3700de8cde5053928560f93167d2db2aae00bce578a743fdc22d8f8be4111920ab45368c77bc4786887107c11e3cd32ee51c176b6aa929a0efb131b5b18258ee1f009c8f94965761e532d34466cbf91eb91458f7379579afc83e36d2f9492c31b6124c35f6e021c7330e135f590f7d8171ddfb3ea6d659807cf0bf0e930e8631abcb7cdeec5eade16151def5dd91dec156eaf7abd58003c5e345387c9bac6bde158a6d696a826dd3230fa650a90bbd857ee25ff8d9c1956e8c6430df1b115177ba1bc6c839ad4653657542c280b4e04ac3aaf6a91e2ab652f74d080c8cb61d1924344e21e4968e19321f1dbd78cac9a0182d22&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=double-hop-gcs%40williams-bobsled-te--conductor.iam.gserviceaccount.com%2F20240718%2Feurope-west1%2Fstorage%2Fgoog4_request&x-goog-date=20240718T124357Z&x-goog-expires=10800&x-goog-signedheaders=host',
    // );

    const objectStorageDestination = await createTestUrlFileDestination(
      agent,
      'https://storage.googleapis.com/will-gcs-test-bucket/gcs-file-source/sftp-numbers.txt?x-goog-signature=3828c1013a123bb8dcfeb840303b5b65459a6fa7fbe5b699695149f46329de9ecd08346cd1edc253d93cfb02e0ee94f3de36ba1aa35711839fc7dd46a83075db741916223365237a60ee5007930dd1488547ce373d34ce7d02a601a72a7e650e1b1b2edab7d8e7f3ca0e9e5a63953b372602443323fef40ee4f4c5188c74e8e2df3db09a10a1658442c9b288879d84b7e1cf4c2a1b5ae74fe6d559e78807813e34fcb26ffae2804894a48a097fdf9804eed909a0d0e5c8f1b1490bc997756f31af316422586141f0058ad77d86492ecf27eadd0ece415249390804e1ce3897a8a6fa1be6638a8c9991613fb8163495dce3f6903f1b835e2c99afcd0bb28af4c9&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=double-hop-gcs%40williams-bobsled-te--conductor.iam.gserviceaccount.com%2F20240719%2Feurope-west1%2Fstorage%2Fgoog4_request&x-goog-date=20240719T061741Z&x-goog-expires=10800&x-goog-signedheaders=host',
    );

    const conn = new Client();

    conn.on('ready', () => {
      console.log('Client :: ready');
      conn.sftp((err: Error, sftp: any) => {
        if (err) throw err;

        // sftp.fastPut('-', 'gcs-numbers.txt', {
        //   concurrency: 64,
        //   customFs: objectStorageSource,
        //   // chunkSize: 131072,
        //   // fileSize: 2_188_895
        //   // 45959
        //   offset: 1_000_000,
        //   length: 1_000_000,
        // }, (err: Error) => {
        //   if (err) throw err;
        //   console.log('File transferred');
        //   conn.end();
        // });

        sftp.fastGet('numbers.txt', '-', {
          concurrency: 64,
          customFs: objectStorageDestination,
          // chunkSize: 131072,
          // fileSize: 2_188_895
          // offset: 1_000_000,
          // length: 1_000_000,
        }, (err: Error) => {
          if (err) throw err;
          console.log('File transferred');
          conn.end();
        });
      });
    }).connect({
      host: 'eu-west-1.sftpcloud.io',
      username: 'test-sftp',
      port: 22,
      password: 'ejbxw4sPo1JQqYmvUQlROpeqFH6gwCb7'
    });
}

main();