import { createTestUrlFileSource } from "./lib/protocol/urlTransfer";
import { Agent, request } from 'node:https';
import Client from './lib/client';

async function main() {

    const httpsAgent = new Agent({ keepAlive: true, maxSockets: 100 });
    const objectStorageSourceInterface = await createTestUrlFileSource({
        get(url: string, options: { headers: Record<string, string> }) {
            console.log('making get request');
            return request(url, {
                method: 'GET',
                headers: options.headers,
                agent: httpsAgent
            });
        }, 
        put(url: string, options: { headers: Record<string, string> }) {
            throw new Error('Not implemented');
        }
    }, 'https://storage.googleapis.com/will-gcs-test-bucket/gcs-file-source/file-small.txt?x-goog-signature=1a5a53545f4805c49994b155fd0157b829d81aa90ed7feb950e888aa6d3989bbe8962cedeb175ecc73e692d80cbefaaf59a622d472b7cb4f78dccd06534291e9c9e0ae454c56528e10d3685e3628474312e5c3f61f4f1b6a8a2f2cd4400ac17414cb8d19e694874797fa85b0d8fce712bb0247172eef52995a87326609fa76c711f05332f59a02b0f42a21b3af794e256c6f516dab7678f85f003bfab72e6779d1cecd31cee20edd84e1da411aefd52ff12648d764d3364b2d439e1f43a70b7cbff3f925e4d527325fb47686c5c62354c1ab1aa0d264744b46b2c75ae8175ee630d6881606e25deca417f3aa4f019cc2f8c8337d416b247a5ee7ada374b37abc&x-goog-algorithm=GOOG4-RSA-SHA256&x-goog-credential=double-hop-gcs%40williams-bobsled-te--conductor.iam.gserviceaccount.com%2F20240715%2Feurope-west1%2Fstorage%2Fgoog4_request&x-goog-date=20240715T083746Z&x-goog-expires=10800&x-goog-signedheaders=host',
    );

    const conn = new Client();

    conn.on('ready', () => {
        console.log('Client :: ready');
        conn.sftp((err: Error, sftp: any) => {
          if (err) throw err;

          sftp.fastPutSled(objectStorageSourceInterface, 'file-small.txt', 'file-small.txt', (err: Error) => {
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

    // fastXfer(objectStorageSourceInterface, dst, 'dummy-path', dstPath, { concurrency: 64 }, (err) => {
    //     if (err) {
    //       console.error('Transfer failed:', err);
    //     } else {
    //       console.log('Transfer completed successfully');
    //     }
    //   });
}

main();