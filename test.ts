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
      'https://storage.googleapis.com/will-gcs-test-bucket/gcs-file-source/sftp-numbers.txt?x-goog-signature=af620afbf74043824e8c85dc23f67c6574893e4a824853707d40867c147ba9838a3ae4ee7d352e6745b3e6c859893c116e1fd04c61f90c85c970279f45b3c1abb5caa92d7d102fbeb93f8b53103a18b9e39678782037c09558efc7a2d6faa020a1dc898b9fb3d425dc156eb3a0274628c1d373598c342ed38ec0f9a72a8e1d2b8cce7f09ae6678befe3e8be7438d2bf3e432a7449985e9cef0332629c5c72250dd4bb71de79bcad7f24723a345b3c180029d817229327ac7767581ae2aee03729c4ab8522bfcaa0ea31bb8019dd5df395fe04dec0647a5a5d87e481e2ddb4171940ecb7189062f1a0f7e21e0a9353f48a1d5864382487e82f665c6dceee030bd&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=double-hop-gcs%40williams-bobsled-te--conductor.iam.gserviceaccount.com%2F20240719%2Feurope-west1%2Fstorage%2Fgoog4_request&x-goog-date=20240719T060759Z&x-goog-expires=10800&x-goog-signedheaders=content-range%3Bhost',
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