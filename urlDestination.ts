import { ClientRequest, IncomingMessage } from "node:http";
interface CallbackFn<T = void> {
  (err: Error | null, extra?: T): void;
}

interface FileDestination {
  open(path: string, flags: string, callback: CallbackFn<any>): void;
  close(handle: any, callback: CallbackFn): void;
  fchmod(handle: any, mode: number, callback: CallbackFn): void;
  chmod(path: string, mode: number, callback: CallbackFn): void;
  write(
    handle: any,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    callback: CallbackFn
  ): void;
}

interface AgentInterface {
  get(
    url: string,
    options: {
      headers: Record<string, string>;
    }
  ): ClientRequest;
  put(
    url: string,
    options: {
      headers: Record<string, string>;
    }
  ): ClientRequest;
}

class PreSignedUrlFileDestination implements FileDestination {
  private chunks: Array<{ start: number; end: number; buffer: Buffer }> = [];
  
  constructor(
    private readonly agent: AgentInterface,
    private readonly url: string
  ) {}

  open(path: string, flags: string, callback: CallbackFn<any>): void {
    console.log("open", { path, flags });
    // We don't need to open anything, so we just call the callback immediately
    callback(null, null);
  }

  close(handle: any, callback: CallbackFn): void {
    try {
      console.log('Closing');
      this.chunks = this.chunks.sort((a, b) => a.start - b.start);
      const fileToSend = Buffer.concat(this.chunks.map(({ buffer }) => buffer));

      const startByte = this.chunks[0].start;
      const endByte = startByte + fileToSend.length - 1;

      console.log('Sending with headers', JSON.stringify({
        'Content-Range': `bytes ${startByte}-${endByte}/${endByte + 1}`,
      }));
      const request = this.agent.put(this.url, {
        headers: {
          'Content-Range': `bytes ${startByte}-${endByte}/${endByte + 1}`,
        },
      });
      request.write(fileToSend);

      request.on("error", (err) => {
        console.error("put request error", err);
        callback(err);
      });

      request.end();

      request.on("response", (stream) => {
        if (!stream.statusCode || stream.statusCode >= 300) {
          console.error("unsuccessful put response", stream.statusCode);

          // TODO: collect the response into a buffer and print it out properly when assembled;
          stream.on("data", (chunk: Buffer) => {
            console.log("Failed put response data", {
              len: chunk.length,
              value: chunk?.toString("utf-8"),
            });
          });

          return callback(new Error(stream.statusMessage));
        }

        stream.once("end", () => {
          callback(null);
          stream.destroy();
        });

        stream.once('readable', () => {});

        stream.once("error", (err) => {
          console.log("errored", err);
          callback(err as Error);
        });
      });
    } catch (err) {
      callback(err as Error);
    }
  }

  fchmod(handle: any, mode: number, callback: CallbackFn): void {
    console.log("fchmod", { handle, mode });
    // We don't need to open anything, so we just call the callback immediately
    callback(null);
  }

  chmod(path: string, mode: number, callback: CallbackFn): void {
    console.log("chmod", { path, mode });
    // We don't need to open anything, so we just call the callback immediately
    callback(null);
  }

  async write(
    handle: any,
    buffer: Buffer,
    offset: number,
    length: number,
    position: number,
    callback: CallbackFn
  ): Promise<void> {
    console.log('Writing', handle, offset, length, position);
    if (offset < 0 || length < 0 || offset + length > buffer.length) {
      throw new Error('Invalid offset or length');
    }

    const data = Buffer.alloc(length);
    buffer.copy(data, 0, offset, offset + length);
    const chunk = {
      start: position,
      end: position + length,
      buffer: data,
    };
    this.chunks.push(chunk);
    callback(null);
  }
}

export async function createTestUrlFileDestination(
  agentIf: AgentInterface,
  url: string,
): Promise<PreSignedUrlFileDestination> {
  return new PreSignedUrlFileDestination(agentIf, url);
}
