# Secure Image CDN Proxy

A production-grade Cloudflare Worker that acts as a secure image CDN proxy with HMAC authentication and edge caching.


## Developer Integration

### Using the CDN in Your Application

The Sendai CDN is available at `https://cdn.sendai.fun` and can be integrated into any application that needs secure, authenticated image proxying.

#### Frontend Integration (JavaScript/TypeScript)

```javascript
class SendaiCDN {
  constructor(secretKey) {
    this.secretKey = secretKey;
    this.baseUrl = 'https://cdn.sendai.fun';
  }

  async generateSignedUrl(imageUrl, expiryMinutes = 60) {
    const crypto = require('crypto');
    const exp = Math.floor(Date.now() / 1000) + (expiryMinutes * 60);
    const message = imageUrl + exp;
    const signature = crypto.createHmac('sha256', this.secretKey).update(message).digest('hex');
    
    const params = new URLSearchParams({
      url: imageUrl,
      sig: signature,
      exp: exp.toString()
    });
    
    return `${this.baseUrl}/cdn?${params.toString()}`;
  }
}

// Usage example
const cdn = new SendaiCDN('your-secret-key');
const proxiedUrl = await cdn.generateSignedUrl('https://example.com/image.jpg', 30);
```

#### Backend Integration (Node.js)

```javascript
const crypto = require('crypto');

function generateCDNUrl(imageUrl, secretKey, expiryMinutes = 60) {
  const exp = Math.floor(Date.now() / 1000) + (expiryMinutes * 60);
  const message = imageUrl + exp;
  const signature = crypto.createHmac('sha256', secretKey).update(message).digest('hex');
  
  const params = new URLSearchParams({
    url: imageUrl,
    sig: signature,
    exp: exp.toString()
  });
  
  return `https://cdn.sendai.fun/cdn?${params.toString()}`;
}

// Usage in Express.js API
app.get('/api/images/:id', (req, res) => {
  const originalImageUrl = `https://storage.example.com/images/${req.params.id}`;
  const proxiedUrl = generateCDNUrl(originalImageUrl, process.env.HMAC_SECRET);
  
  res.json({ imageUrl: proxiedUrl });
});
```

#### React Component Example

```jsx
import { useState, useEffect } from 'react';

const SecureImage = ({ src, alt, secretKey, ...props }) => {
  const [proxiedSrc, setProxiedSrc] = useState('');

  useEffect(() => {
    const generateProxiedUrl = async () => {
      const exp = Math.floor(Date.now() / 1000) + 3600; // 1 hour
      const message = src + exp;
      const signature = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secretKey),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      ).then(key => 
        crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message))
      ).then(signature => 
        Array.from(new Uint8Array(signature))
          .map(b => b.toString(16).padStart(2, '0'))
          .join('')
      );

      const params = new URLSearchParams({
        url: src,
        sig: signature,
        exp: exp.toString()
      });

      setProxiedSrc(`https://cdn.sendai.fun/cdn?${params.toString()}`);
    };

    if (src) {
      generateProxiedUrl();
    }
  }, [src, secretKey]);

  return proxiedSrc ? <img src={proxiedSrc} alt={alt} {...props} /> : null;
};
```

#### Python Integration

```python
import hmac
import hashlib
import time
from urllib.parse import urlencode

def generate_cdn_url(image_url, secret_key, expiry_minutes=60):
    exp = int(time.time()) + (expiry_minutes * 60)
    message = f"{image_url}{exp}"
    signature = hmac.new(
        secret_key.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    params = {
        'url': image_url,
        'sig': signature,
        'exp': str(exp)
    }
    
    return f"https://cdn.sendai.fun/cdn?{urlencode(params)}"
```

### Best Practices

1. **Keep your secret key secure** - Store it in environment variables, never in client-side code
2. **Set appropriate expiry times** - Balance security with caching efficiency
3. **Use HTTPS only** - The CDN only accepts HTTPS image URLs
4. **Handle errors gracefully** - Implement fallbacks for failed CDN requests
5. **Cache signed URLs** - Generate URLs server-side and cache them to reduce computation

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