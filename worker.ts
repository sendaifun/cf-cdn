interface Env {
  HMAC_SECRET: string;
}

interface CDNParams {
  url: string;
  sig: string;
  exp: string;
}

interface CDNResponse {
  success: boolean;
  message?: string;
  cacheHit?: boolean;
}

interface ValidationResult {
  isValid: boolean;
  error?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const { pathname, searchParams } = new URL(request.url);


      if (pathname !== '/cdn') {
        return new Response('Not Found', { status: 404 });
      }

      const params = extractParams(searchParams);

      console.log(params)

      if (!params.url || !params.sig || !params.exp) {
        return new Response('Missing required parameters: url, sig, exp', { status: 400 });
      }

      const validation = validateRequest(params);
      if (!validation.isValid) {
        return new Response(validation.error!, { status: 400 });
      }

      const isValidSignature = await verifyHMACSignature(params.url + params.exp, params.sig, env.HMAC_SECRET);
      if (!isValidSignature) {
        return new Response('Invalid signature', { status: 403 });
      }

      const cache = caches.default;
      const cacheKey = new Request(params.url, { method: 'GET' });

      let response = await cache.match(cacheKey);
      let cacheHit = !!response;

      if (!response) {
        try {
          response = await fetchImage(params.url);

          const modifiedResponse = createCachedResponse(response);
          ctx.waitUntil(cache.put(cacheKey, modifiedResponse.clone()));
          response = modifiedResponse;
        } catch (error) {
          console.error('Failed to fetch image:', error);
          return new Response('Failed to fetch image', { status: 502 });
        }
      } else {
        response = addCORSHeaders(response);
      }

      logRequest(params.url, cacheHit);
      return response;

    } catch (error) {
      console.error('CDN Error:', error);
      return new Response('Internal Server Error', { status: 500 });
    }
  },
};

function extractParams(searchParams: URLSearchParams): CDNParams {
  return {
    url: searchParams.get('url') || '',
    sig: searchParams.get('sig') || '',
    exp: searchParams.get('exp') || ''
  };
}

function validateRequest(params: CDNParams): ValidationResult {
  if (!params.url.startsWith('https://')) {
    return { isValid: false, error: 'Only HTTPS URLs are allowed' };
  }

  const expiry = parseInt(params.exp);
  if (isNaN(expiry) || expiry < Date.now() / 1000) {
    return { isValid: false, error: 'Invalid or expired timestamp' };
  }

  try {
    new URL(params.url);
  } catch {
    return { isValid: false, error: 'Invalid URL format' };
  }

  return { isValid: true };
}

async function verifyHMACSignature(message: string, signature: string, secret: string): Promise<boolean> {
  try {
    if (!secret) {
      throw new Error('HMAC_SECRET environment variable not set');
    }

    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signatureBuffer = hexToBuffer(signature);
    const messageBuffer = encoder.encode(message);

    return await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      messageBuffer
    );
  } catch (error) {
    console.error('HMAC verification error:', error);
    return false;
  }
}

function hexToBuffer(hex: string): ArrayBuffer {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }

  const buffer = new ArrayBuffer(hex.length / 2);
  const view = new Uint8Array(buffer);

  for (let i = 0; i < hex.length; i += 2) {
    view[i / 2] = parseInt(hex.substr(i, 2), 16);
  }

  return buffer;
}

async function fetchImage(url: string): Promise<Response> {
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'User-Agent': 'Cloudflare-CDN-Proxy/1.0'
    }
  });

  if (!response.ok) {
    throw new Error(`Failed to fetch image: ${response.status} ${response.statusText}`);
  }

  const contentType = response.headers.get('content-type');
  if (!contentType || !contentType.startsWith('image/')) {
    throw new Error('Response is not an image');
  }

  return response;
}

function createCachedResponse(response: Response): Response {
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: {
      ...Object.fromEntries(response.headers.entries()),
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Access-Control-Allow-Origin': '*'
    }
  });
}

function addCORSHeaders(response: Response): Response {
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: {
      ...Object.fromEntries(response.headers.entries()),
      'Access-Control-Allow-Origin': '*'
    }
  });
}

function logRequest(url: string, cacheHit: boolean): void {
  console.log(`CDN Request: ${url} | Cache: ${cacheHit ? 'HIT' : 'MISS'}`);
}