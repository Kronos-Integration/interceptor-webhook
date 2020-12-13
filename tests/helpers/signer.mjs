import { createHmac } from "crypto";

export signer(buffer, algorithm, secret) {
  const hmac = createHmac(algorithm, secret);
  hmac.update(buffer, 'utf-8');
  return algorithm + '=' + hmac.digest('hex');
}

