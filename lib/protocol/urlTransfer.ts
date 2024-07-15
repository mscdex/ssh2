import { ClientRequest, IncomingMessage } from 'node:http';
import { S3Client, HeadObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

interface FileSource {
  open(path: string, flags: string, callback: (err: Error | null, handle: any) => void): void;
  close(handle: any, callback: (err: Error | null) => void): void;
  fstat(handle: any, callback: (err: Error | null, stats: { size: number }) => void): void;
  stat(path: string, callback: (err: Error | null, stats: { size: number }) => void): void;
  read(
    handle: any,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    callback: (err: Error | null, bytesRead: number, buffer: Buffer | null) => void
  ): void;
}

interface PreSignedChunk {
  url: string;
  start: number;
  end: number;
}

interface AgentInterface {
  get(url: string, options: {
    headers: Record<string, string>
  }): ClientRequest
  put(url: string, options: {
    headers: Record<string, string>
  }): ClientRequest
}


class PreSignedUrlFileSource implements FileSource {
  private readonly chunks: PreSignedChunk[];
  private fileSize: number;
  private getRequest: Array<ClientRequest | null> = [];
  private getStream: Array<IncomingMessage | null> = [];
  private streamChunks: Array<{buffer: Array<Buffer>, length: number}> = [];

  constructor(private readonly agent: AgentInterface, chunks: PreSignedChunk[]) {
    this.chunks = chunks.sort((a, b) => a.start - b.start);
    this.fileSize = this.chunks[this.chunks.length - 1].end + 1;
  }

  open(path: string, flags: string, callback: (err: Error | null, handle: any) => void): void {
    console.log('open', { path, flags });
    // We don't need to open anything, so we just call the callback immediately
    callback(null, null);
  }

  close(handle: any, callback: (err: Error | null) => void): void {
    console.log('close', { handle });
    // We don't need to close anything, so we just call the callback immediately
    callback(null);
  }

  fstat(handle: any, callback: (err: Error | null, stats: { size: number }) => void): void {
    console.log('fstat', { handle });
    callback(null, { size: this.fileSize });
  }

  stat(path: string, callback: (err: Error | null, stats: { size: number }) => void): void {
    console.log('stat', { path });
    callback(null, { size: this.fileSize });
  }

  async read(
    handle: any,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    callback: (err: Error | null, bytesRead: number, buffer: Buffer | null) => void
  ): Promise<void> {
    // console.log('read', { handle, buffer, offset, length, position });

    try {
      const chunkIndex = this.findChunk(position);
      const getStreamPromise = new Promise<IncomingMessage>((resolve, reject) => {
        const chunk = this.chunks[chunkIndex];
        if (!chunk) {
          console.error('No chunk found for position', position);
          throw new Error('Position out of bounds');
        }

        if(!this.getRequest[chunkIndex]) {
          const chunkOffset = chunk.start;
          const readLength = Math.min(length, chunk.end - position + 1);
    
          console.log('---> Getting chunk', chunkIndex, chunkOffset, readLength, position, chunk);
          this.getRequest[chunkIndex] = this.agent.get(chunk.url, {
            headers: {
              'Range': `bytes=${chunkOffset}-${chunkOffset + readLength - 1}`
            }
          });

          this.getRequest[chunkIndex].on('error', (err) => {
            console.error('get request error', err);
            callback(err, 0, null);
            reject(err);
          });
    
          this.getRequest[chunkIndex].end();
        }

        this.getRequest[chunkIndex].on('response', (res) => {
          // console.log('response', res.statusCode);

          if (!res.statusCode || res.statusCode >= 300) {
            console.error('unsuccessful get response', res.statusCode);

            // TODO: collect the response into a buffer and print it out properly when assembled;
            res.on('data', (chunk: Buffer) => {
              console.log('Failed get response data', { len: chunk.length, value: chunk?.toString('utf-8') });
            });

            // try {
            //   destroyPut();
            // } catch (e) {
            //   console.error('error destroying put request', e);
            // }
            return callback(new Error(res.statusMessage), 0, null);
          } else {
            // console.log('successful get response', res.statusCode);

            this.getStream[chunkIndex] = res;
            resolve(this.getStream[chunkIndex]);
          }
        });
      });

      const getStream = await getStreamPromise;

      getStream.on('data', (bufferChunk: Buffer) => {
        if (!this.streamChunks[chunkIndex]) {
          this.streamChunks[chunkIndex] = { buffer: [], length: 0 };
        }
        this.streamChunks[chunkIndex].buffer.push(bufferChunk);
        this.streamChunks[chunkIndex].length += bufferChunk.length;
      });

      getStream.once('end', () => {
        const data = Buffer.concat(this.streamChunks[chunkIndex].buffer, this.streamChunks[chunkIndex].length);

        // Calculate how much data we can actually copy to the buffer
        const bytesToCopy = Math.min(data.length, length);

        // Copy the data into the provided buffer at the specified offset
        console.log('Stream ended', chunkIndex, this.streamChunks[chunkIndex].buffer.length, this.streamChunks[chunkIndex].length, bytesToCopy)
        data.copy(buffer, offset, 0, bytesToCopy);
        callback(null, bytesToCopy, data);
        getStream.destroy();
      });

      getStream.once('error', (err) => {
        console.log('errored', err)
        callback(err as Error, 0, null);
      });

      // const getStream = await getStreamPromise;
      

      // const chunk = getStream.read();
      // let data = Buffer();

      // // Listen for data chunks
      // getStream.on('data', (chunk) => {
      //   data += chunk;
      // });

      // // Listen for the end of the response
      // getStream.on('end', () => {
      //   data.copy(buffer, offset, 0, length);
      //   callback(null, data.length, data);
      //   console.log('Response has ended. Full data:', data);
      // });
      // if (chunk === null) {
      //   // now we need to wait until some data is available
      //   getStream.once('end', (data) => {
      //     console.log('data', data.length);
      //     data.copy(buffer, offset, 0, length);
      //     callback(null, data.length, data);
      //   });
      // } else {
      //   chunk.copy(buffer, offset, 0, length);
      //   callback(null, chunk.length, chunk);
      // }
    } catch (err) {
      callback(err as Error, 0, null);
    }
  }

  private findChunk(position: number): number {
    console.log('findChunk', { position });
    return this.chunks.findIndex(chunk => chunk.start <= position && chunk.end >= position);
  }
}



async function createPreSignedUrlFileSource(
  agentIf: AgentInterface,
  bucket: string,
  key: string,
  region: string,
  chunkCount: number = 64,
  expiresIn: number = 3600 // URL expiration time in seconds
): Promise<PreSignedUrlFileSource> {
  const s3Client = new S3Client({ region });

  // Get object size
  const headObjectCommand = new HeadObjectCommand({ Bucket: bucket, Key: key });
  const headObjectResponse = await s3Client.send(headObjectCommand);
  const objectSize = headObjectResponse.ContentLength;

  if (!objectSize) {
    throw new Error("Unable to determine object size");
  }

  const chunkSize = Math.ceil(objectSize / chunkCount);
  const chunks: PreSignedChunk[] = [];

  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize - 1, objectSize - 1);

    const getObjectCommand = new GetObjectCommand({
      Bucket: bucket,
      Key: key,
      Range: `bytes=${start}-${end}`
    });

    const url = await getSignedUrl(s3Client, getObjectCommand, { expiresIn });

    chunks.push({ url, start, end });
  }

  return new PreSignedUrlFileSource(agentIf, chunks);
}

export async function createTestUrlFileSource(
  agentIf: AgentInterface,
  url: string,
  chunkSize: number = 32768
): Promise<PreSignedUrlFileSource> {
  // First, we need to determine the size of the file
  const headResponse = await fetch(url, { method: 'HEAD' });
  
  if (!headResponse.ok) {
    throw new Error(`HTTP error! status: ${headResponse.status}`);
  }
  
  const contentLength = headResponse.headers.get('Content-Length');
  
  if (!contentLength) {
    throw new Error('Content-Length header is missing');
  }
  
  const fileSize = parseInt(contentLength, 10);
  console.log('HEAD response', headResponse, fileSize);
  
  if (isNaN(fileSize)) {
    throw new Error('Invalid Content-Length header');
  }

  const chunkCount = Math.ceil(fileSize / chunkSize);
  const chunks: PreSignedChunk[] = [];

  for (let i = 0; i < chunkCount; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize - 1, fileSize - 1);

    chunks.push({
      url: url,  // We use the same URL for all chunks
      start,
      end
    });
  }
  console.log('Total chunks', chunks.length);

  return new PreSignedUrlFileSource(agentIf, chunks);
}
