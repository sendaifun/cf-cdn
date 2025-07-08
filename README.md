# Secure Image CDN Proxy

A production-grade Cloudflare Worker that acts as a secure image CDN proxy with HMAC authentication and edge caching.

## Features

- **HMAC Authentication**: Validates requests using HMAC-SHA256 signatures
- **Expiry Protection**: Prevents replay attacks with timestamp validation
- **HTTPS Only**: Rejects non-HTTPS image URLs
- **Edge Caching**: Leverages Cloudflare's global edge cache
- **CORS Support**: Includes CORS headers for frontend compatibility
- **Image Validation**: Ensures fetched content is actually an image
- **Streaming**: Efficient response streaming without full buffering

## Usage

### Request Format

```
GET /cdn?url=<encoded_url>&sig=<hmac_signature>&exp=<unix_timestamp>
```

### Parameters

- `url`: Base64 or URL-encoded HTTPS image URL
- `sig`: HMAC-SHA256 signature of `url + exp` using your secret key
- `exp`: Unix timestamp (seconds) when the link expires

### Example

```bash
# Generate signature (Node.js example)
const crypto = require('crypto');
const url = 'https://example.com/image.jpg';
const exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour from now
const message = url + exp;
const signature = crypto.createHmac('sha256', 'your-secret-key').update(message).digest('hex');

# Request URL
https://your-worker.example.workers.dev/cdn?url=https%3A%2F%2Fexample.com%2Fimage.jpg&sig=${signature}&exp=${exp}
```

## Deployment

1. Configure your `HMAC_SECRET` environment variable in Cloudflare Workers dashboard
2. Deploy using Wrangler:

```bash
wrangler publish
```

## Security

- All image URLs must use HTTPS
- Signatures expire based on the `exp` parameter
- Invalid signatures return 403 Forbidden
- Only image content-types are cached and served

## Cache Behavior

- Images are cached at Cloudflare's edge for 1 year (immutable)
- Cache key is based on the original image URL
- Cache misses fetch from origin and store in edge cache
- Cache hits are served directly from edge