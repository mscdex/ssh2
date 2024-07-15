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
    console.log('read', { handle, buffer, offset, length, position });


    try {
      const getStreamPromise = new Promise<IncomingMessage>((resolve, reject) => {
      const chunkIndex = this.findChunk(position);
      const chunk = this.chunks[chunkIndex];
      if (!chunk) {
        throw new Error('Position out of bounds');
      }

      if(!this.getRequest[chunkIndex]) {
        const chunkOffset = position - chunk.start;
        const readLength = Math.min(length, chunk.end - position + 1);
  
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
        console.log('response', res.statusCode);

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
          console.log('successful get response', res.statusCode);

          this.getStream[chunkIndex] = res;
          resolve(this.getStream[chunkIndex]);
        }
      });
    });

      const getStream = await getStreamPromise;

      const chunk = getStream.read(length);
      if(chunk === null) {
        // now we need to wait until some data is available
        getStream.once('data', (data) => {
          console.log('data');
          
          callback(null, data.length, data);
        });
      } else {
        callback(null, chunk.length, chunk);
      }
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
  chunkCount: number = 64
): Promise<PreSignedUrlFileSource> {
  // First, we need to determine the size of the file
  const headResponse = await fetch(url, { method: 'HEAD' });
  
  if (!headResponse.ok) {
    throw new Error(`HTTP error! status: ${headResponse.status}`);
  }
  console.log('HEAD response', headResponse);
  
  const contentLength = headResponse.headers.get('Content-Length');
  
  if (!contentLength) {
    throw new Error('Content-Length header is missing');
  }
  
  const fileSize = parseInt(contentLength, 10);
  
  if (isNaN(fileSize)) {
    throw new Error('Invalid Content-Length header');
  }

  const chunkSize = Math.ceil(fileSize / chunkCount);
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
  console.log('chunks', chunks);

  return new PreSignedUrlFileSource(agentIf, chunks);
}
