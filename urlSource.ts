import { ClientRequest, IncomingMessage } from 'node:http';
interface CallbackFn<T = void> {
  (err: Error | null, extra?: T): void
}

interface FileSource {
  open(path: string, flags: string, callback: CallbackFn<any>): void;
  close(handle: any, callback: CallbackFn): void;
  fstat(handle: any, callback: CallbackFn<{ size: number }>): void;
  stat(path: string, callback: CallbackFn<{ size: number }>): void;
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
  private streamChunksN: Array<Promise<{ buffer: Array<Buffer>, length: number }>> = [];


  private getRequest: Array<ClientRequest | null> = [];
  private getStream: Array<IncomingMessage | null> = [];
  private streamChunks: Array<{ buffer: Array<Buffer>, length: number }> = [];

  constructor(private readonly agent: AgentInterface, chunks: PreSignedChunk[]) {
    this.chunks = chunks.sort((a, b) => a.start - b.start);
    this.fileSize = this.chunks[this.chunks.length - 1].end + 1;
  }

  open(path: string, flags: string, callback: CallbackFn<any>): void {
    console.log('open', { path, flags });
    // We don't need to open anything, so we just call the callback immediately
    callback(null, null);
  }

  close(handle: any, callback: CallbackFn): void {
    console.log('close', { handle });
    // We don't need to close anything, so we just call the callback immediately
    callback(null);
  }

  fstat(handle: any, callback: CallbackFn<{ size: number }>): void {
    console.log('fstat', { handle });
    callback(null, { size: this.fileSize });
  }

  stat(path: string, callback: CallbackFn<{ size: number }>): void {
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
    try {
      const chunkIndex = this.findChunk(position);
      
      if (!this.streamChunksN[chunkIndex]) {
        this.streamChunksN[chunkIndex] = new Promise((resolve, reject) => {
          const chunk = this.chunks[chunkIndex];
          if (!chunk) {
            console.error('No chunk found for position', position);
            throw new Error('Position out of bounds');
          }
          console.log(`Getting chunk number ${chunkIndex} for position ${position} with offset ${offset} and length ${length}`);

          const chunkResponse: { buffer: Array<Buffer>, length: number } = { buffer: [], length: 0 };
          const chunkOffset = chunk.start;
          // const readLength = Math.min(length, chunk.end - position + 1);
          const readLength = chunk.end;
    
          const chunkRequest = this.agent.get(chunk.url, {
            headers: {
              'Range': `bytes=${chunkOffset}-${chunkOffset + readLength - 1}`
            }
          });

          chunkRequest.on('error', (err) => {
            console.error('get request error', err);
            return reject(err);
          });
    
          chunkRequest.end();

          chunkRequest.on('response', (res) => {
            if (!res.statusCode || res.statusCode >= 300) {
              console.error('unsuccessful get response', res.statusCode);
  
              // TODO: collect the response into a buffer and print it out properly when assembled;
              res.on('data', (chunk: Buffer) => {
                console.log('Failed get response data', { len: chunk.length, value: chunk?.toString('utf-8') });
              });
  
              return reject(new Error(res.statusMessage));
            }

            res.on('data', (bufferChunk: Buffer) => {
              chunkResponse.buffer.push(bufferChunk);
              chunkResponse.length += bufferChunk.length;
            });
      
            res.once('end', () => {
              res.destroy();
              return resolve(chunkResponse);
            });
      
            res.once('error', (err) => {
              console.log('errored', err)
              return reject(err as Error);
            });

          });

        });
      }

      const chunkBuffer = await this.streamChunksN[chunkIndex];
      const data = Buffer.concat(chunkBuffer.buffer, chunkBuffer.length);
      const bytesToCopy = Math.min(data.length, length);

      data.copy(buffer, offset, 0, bytesToCopy);
      callback(null, bytesToCopy, data);



      // const getStreamPromise = new Promise<IncomingMessage>((resolve, reject) => {
      //   const chunk = this.chunks[chunkIndex];
      //   if (!chunk) {
      //     console.error('No chunk found for position', position);
      //     throw new Error('Position out of bounds');
      //   }
      //   console.log(`Getting chunk number ${chunkIndex} for position ${position} with offset ${offset} and length ${length}`);
      //   if(!this.getRequest[chunkIndex]) {
      //     const chunkOffset = chunk.start;
      //     // const readLength = Math.min(length, chunk.end - position + 1);
      //     const readLength = chunk.end;
    
      //     this.getRequest[chunkIndex] = this.agent.get(chunk.url, {
      //       headers: {
      //         'Range': `bytes=${chunkOffset}-${chunkOffset + readLength - 1}`
      //       }
      //     });

      //     this.getRequest[chunkIndex].on('error', (err) => {
      //       console.error('get request error', err);
      //       callback(err, 0, null);
      //       reject(err);
      //     });
    
      //     this.getRequest[chunkIndex].end();
      //   }

      //   this.getRequest[chunkIndex].on('response', (res) => {
          
      //     if (!res.statusCode || res.statusCode >= 300) {
      //       console.error('unsuccessful get response', res.statusCode);

      //       // TODO: collect the response into a buffer and print it out properly when assembled;
      //       res.on('data', (chunk: Buffer) => {
      //         console.log('Failed get response data', { len: chunk.length, value: chunk?.toString('utf-8') });
      //       });

      //       return callback(new Error(res.statusMessage), 0, null);
      //     } else {
      //       this.getStream[chunkIndex] = res;
      //       resolve(this.getStream[chunkIndex]);
      //     }
      //   });
      // });

      // const getStream = await getStreamPromise;

      // getStream.on('data', (bufferChunk: Buffer) => {
      //   if (!this.streamChunks[chunkIndex]) {
      //     this.streamChunks[chunkIndex] = { buffer: [], length: 0 };
      //   }
      //   this.streamChunks[chunkIndex].buffer.push(bufferChunk);
      //   this.streamChunks[chunkIndex].length += bufferChunk.length;
      // });

      // getStream.once('end', () => {
      //   const data = Buffer.concat(this.streamChunks[chunkIndex].buffer, this.streamChunks[chunkIndex].length);
      //   // const bytesToCopy = Math.min(data.length, length);
      //   const bytesToCopy = data.length;

      //   data.copy(buffer, offset, 0, bytesToCopy);
      //   callback(null, bytesToCopy, data);
      //   getStream.destroy();
      // });

      // getStream.once('error', (err) => {
      //   console.log('errored', err)
      //   callback(err as Error, 0, null);
      // });
    } catch (err) {
      callback(err as Error, 0, null);
    }
  }

  private findChunk(position: number): number {
    return this.chunks.findIndex(chunk => chunk.start <= position && chunk.end >= position);
  }
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
  console.log('HEAD response', fileSize);
  
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
