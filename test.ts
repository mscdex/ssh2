import { createTestUrlFileSource } from "./lib/protocol/urlSource";
import { Agent, request } from 'node:https';
import Client from './lib/client';
import { createTestUrlFileDestination } from "./lib/protocol/urlDestination";

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
    //   'https://storage.googleapis.com/will-gcs-test-bucket/gcs-file-source/100-mb-example-jpg.jpg?x-goog-signature=356e7861d78e1e5f380afd84f2fd08b6e16fd07adc2f675d41f920f8cce8d7776d103171674c2b5ea46776286e09fd700be4939b42426319a3a4dbc64d8af254cd1c192f5053db43a79dc4d845f87f43e55b63d0f5f2510a1cacb2da1fb312e61acf67e5e682cbc19058a59d567ac02c192aee8a862afe2a5e40c87f1af5b8ceae07e312c02ecc10949f66d9a730a5aee2d97aaf59c352febb6d712c70a614542748eabc427779fc929d4a09865c2092155dbcb6a9072294b06eb233faaae1bc134ff891e26f2d7674ad83e9e37087edd43d6c6297fa354f9792226bcedb087ed248f5f31ad251e589280bf1293d91d5df4fe0887fc7ddd3fec3418e4096fef5&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=double-hop-gcs%40williams-bobsled-te--conductor.iam.gserviceaccount.com%2F20240715%2Feurope-west1%2Fstorage%2Fgoog4_request&x-goog-date=20240715T135558Z&x-goog-expires=10800&x-goog-signedheaders=host',
    // );

    const objectStorageDestination = await createTestUrlFileDestination(
      agent,
      'https://storage.googleapis.com/will-gcs-test-bucket/gcs-file-source/image.png?x-goog-signature=1b28c1a9ffccd629916f1a2e53eaf9e8c301076906a994969dd29c4a94414d47a08441d1532001bc5e641d28ca6e7ec3ccb54644fd9d57fc1c38e3da90f25476e8730b193075e260c027914953c1edacd663f34ae555ba7a819af8c29f606bbeb3ff618fac27dc08f853a8e4dbcf6a5c203ebe2d24611e61da28119acdd4d4fda0f550ddc26491c47c75cfcc52f991c14d141cad780e2f03ea7426a1df90a1840e1f3ffd1c603e0efc1f84c8e8b90d3021b396782087d4e24587fef07743ee3b28a3c877bf34853220b7e216fd3db480a60c65109c224901a30a7a6a2140924657d2972c3b73d3f7e6edc90bcbc15ce19806553dccfefe2a41cf3e809864942f&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=double-hop-gcs%40williams-bobsled-te--conductor.iam.gserviceaccount.com%2F20240717%2Feurope-west1%2Fstorage%2Fgoog4_request&x-goog-date=20240717T122325Z&x-goog-expires=10800&x-goog-signedheaders=host',
    );

    const conn = new Client();

    conn.on('ready', () => {
      console.log('Client :: ready');
      conn.sftp((err: Error, sftp: any) => {
        if (err) throw err;

        // sftp.fastPut('-', '100mb.jpg', { concurrency: 64, customFs: objectStorageDestination }, (err: Error) => {
        //   if (err) throw err;
        //   console.log('File transferred');
        //   conn.end();
        // });

        sftp.fastGet('image.png', '-', {
          concurrency: 64,
          customFs: objectStorageDestination,
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