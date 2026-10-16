import { lookup } from "node:dns/promises";
import http, {
  type IncomingHttpHeaders,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import net, { isIP, type Socket } from "node:net";
import type { Duplex } from "node:stream";

type ResolvedAddress = { address: string; family: number };

export class BrowserPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowserPolicyError";
  }
}

function isPublicAddress(address: string): boolean {
  const version = isIP(address);

  if (version === 4) {
    const parts = address.split(".").map(Number);
    const [first, second, third] = parts;

    if (first === undefined || second === undefined || third === undefined) {
      return false;
    }

    if (
      first === 0 ||
      first === 10 ||
      first === 127 ||
      first >= 224 ||
      (first === 100 && second >= 64 && second <= 127) ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) ||
      (first === 192 && second === 0) ||
      (first === 192 && second === 88 && third === 99) ||
      (first === 192 && second === 0 && third === 2) ||
      (first === 198 && (second === 18 || second === 19)) ||
      (first === 198 && second === 51 && third === 100) ||
      (first === 203 && second === 0 && third === 113)
    ) {
      return false;
    }

    return true;
  }

  if (version === 6) {
    const normalized = address.split("%")[0]?.toLowerCase() ?? "";
    const firstGroup = normalized.split(":")[0] ?? "";
    const firstNibble = Number.parseInt(firstGroup[0] ?? "", 16);

    // Only global unicast addresses (2000::/3) are eligible. This excludes
    // loopback, link-local, unique-local, IPv4-mapped, and unspecified ranges.
    if (firstNibble !== 2 && firstNibble !== 3) {
      return false;
    }

    if (
      normalized.startsWith("2001:db8:") ||
      normalized.startsWith("2001:10:") ||
      normalized.startsWith("2001:20:")
    ) {
      return false;
    }

    return true;
  }

  return false;
}

function normalizeHost(hostname: string): string {
  return hostname.startsWith("[") && hostname.endsWith("]")
    ? hostname.slice(1, -1)
    : hostname;
}

export async function resolvePublicAddress(
  hostname: string,
): Promise<ResolvedAddress> {
  const host = normalizeHost(hostname).toLowerCase();

  if (
    !host ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".test") ||
    host.endsWith(".invalid") ||
    host.endsWith(".example")
  ) {
    throw new BrowserPolicyError(
      "Only public websites on the internet can be opened.",
    );
  }

  if (isIP(host)) {
    if (!isPublicAddress(host)) {
      throw new BrowserPolicyError(
        "Private and internal network addresses are blocked.",
      );
    }
    return { address: host, family: isIP(host) };
  }

  let addresses: ResolvedAddress[];
  try {
    addresses = await lookup(host, { all: true, verbatim: true });
  } catch {
    throw new BrowserPolicyError("This website address could not be resolved.");
  }

  if (
    addresses.length === 0 ||
    addresses.some(({ address }) => !isPublicAddress(address))
  ) {
    throw new BrowserPolicyError(
      "This website resolves to a private or restricted network address.",
    );
  }

  const address = addresses[0];
  if (!address) {
    throw new BrowserPolicyError("This website address could not be resolved.");
  }
  return address;
}

function getAllowedWebTarget(input: string, defaultProtocol: "http:" | "https:") {
  let target: URL;
  try {
    target = new URL(input, `${defaultProtocol}//invalid.local`);
  } catch {
    throw new BrowserPolicyError("Enter a valid public website URL.");
  }

  if (
    (target.protocol !== "http:" && target.protocol !== "https:") ||
    target.username ||
    target.password
  ) {
    throw new BrowserPolicyError(
      "Only public http:// and https:// websites can be opened.",
    );
  }

  const expectedPort = target.protocol === "https:" ? "443" : "80";
  if (target.port && target.port !== expectedPort) {
    throw new BrowserPolicyError(
      "For safety, browser sessions only connect to standard web ports (80 and 443).",
    );
  }

  return target;
}

export async function validatePublicWebUrl(input: string): Promise<string> {
  const target = getAllowedWebTarget(input, "https:");
  await resolvePublicAddress(target.hostname);
  return target.toString();
}

function writeProxyError(
  socket: Duplex,
  status: number,
  message: string,
): void {
  if (socket.destroyed) return;
  socket.end(
    `HTTP/1.1 ${status} ${status === 403 ? "Forbidden" : "Bad Gateway"}\r\n` +
      "Connection: close\r\n" +
      "Content-Type: text/plain; charset=utf-8\r\n" +
      `Content-Length: ${Buffer.byteLength(message)}\r\n\r\n${message}`,
  );
}

function writeResponseError(
  response: ServerResponse,
  status: number,
  message: string,
): void {
  if (response.headersSent) {
    response.destroy();
    return;
  }
  response.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "content-length": Buffer.byteLength(message),
    connection: "close",
  });
  response.end(message);
}

function requestHeaders(headers: IncomingHttpHeaders, host: string) {
  const outgoing = { ...headers };
  delete outgoing["proxy-connection"];
  delete outgoing["proxy-authorization"];
  outgoing.host = host;
  return outgoing;
}

async function handleHttpRequest(
  request: IncomingMessage,
  response: ServerResponse,
): Promise<void> {
  try {
    if (!request.url) {
      writeResponseError(response, 400, "Invalid proxy request.");
      return;
    }

    const target = getAllowedWebTarget(request.url, "http:");
    const address = await resolvePublicAddress(target.hostname);
    const port = target.protocol === "https:" ? 443 : 80;
    const upstream = http.request(
      {
        hostname: address.address,
        family: address.family,
        port,
        method: request.method,
        path: `${target.pathname}${target.search}`,
        headers: requestHeaders(request.headers, target.host),
        agent: false,
      },
      (upstreamResponse) => {
        response.writeHead(
          upstreamResponse.statusCode ?? 502,
          upstreamResponse.statusMessage,
          upstreamResponse.headers,
        );
        upstreamResponse.pipe(response);
      },
    );

    upstream.on("error", () => {
      writeResponseError(response, 502, "The website could not be reached.");
    });
    request.on("aborted", () => upstream.destroy());
    request.pipe(upstream);
  } catch (error) {
    const blocked = error instanceof BrowserPolicyError;
    writeResponseError(
      response,
      blocked ? 403 : 502,
      blocked ? error.message : "The website could not be reached.",
    );
  }
}

async function handleConnect(
  request: IncomingMessage,
  client: Duplex,
  head: Buffer,
): Promise<void> {
  let remote: Socket | undefined;

  try {
    if (!request.url) {
      writeProxyError(client, 400, "Invalid proxy request.");
      return;
    }

    const target = getAllowedWebTarget(`https://${request.url}`, "https:");
    const address = await resolvePublicAddress(target.hostname);
    remote = net.connect({
      host: address.address,
      family: address.family,
      port: 443,
    });
    remote.setTimeout(30_000);
    remote.once("timeout", () => remote?.destroy());
    remote.once("connect", () => {
      if (client.destroyed || !remote) {
        remote?.destroy();
        return;
      }
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) remote.write(head);
      remote.pipe(client);
      client.pipe(remote);
    });
    remote.once("error", () => {
      writeProxyError(client, 502, "The website could not be reached.");
    });
    client.once("error", () => remote?.destroy());
    client.once("close", () => remote?.destroy());
  } catch (error) {
    const blocked = error instanceof BrowserPolicyError;
    writeProxyError(
      client,
      blocked ? 403 : 502,
      blocked ? error.message : "The website could not be reached.",
    );
    remote?.destroy();
  }
}

export async function startSecureBrowserProxy(): Promise<{
  url: string;
  close: () => Promise<void>;
}> {
  const server = http.createServer((request, response) => {
    void handleHttpRequest(request, response);
  });
  server.on("connect", (request, socket, head) => {
    void handleConnect(request, socket, head);
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address();
  if (!address || typeof address === "string") {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error("The secure browser proxy did not start.");
  }

  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}
