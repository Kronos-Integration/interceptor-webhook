import { createHmac } from "crypto";

export function signer(buffer, algorithm, secret) {
  const hmac = createHmac(algorithm, secret);
  hmac.update(buffer, "utf-8");
  return algorithm + "=" + hmac.digest("hex");
}
