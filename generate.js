const crypto = require('crypto');

const secret = 'YOUR_SECRET_KEY'

function generateSignedUrl(url, options = {}) {
  const {
    expirationSeconds = 3600, // Default 1 hour
    baseUrl = 'https://cdn.sendai.fun/cdn'
  } = options;

  const exp = Math.floor(Date.now() / 1000) + expirationSeconds;
  const message = url + exp;
  const signature = crypto.createHmac('sha256', secret).update(message).digest('hex');

  // Construct the signed URL
  const encodedUrl = encodeURIComponent(url);
  return `${baseUrl}?url=${encodedUrl}&sig=${signature}&exp=${exp}`;
}


console.log(generateSignedUrl('https://ipfs.io/ipfs/QmagKp8JJXaymvrSmCCKdTVCspyFSafbTTou5ySpsJzUnK'));