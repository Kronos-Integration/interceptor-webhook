import { createHmac } from "crypto";
import { Interceptor } from "@kronos-integration/interceptor";
import { prepareAttributesDefinitions, secret_attribute } from "pacc";

/**
 *
 */
export class GithubHookInterceptor extends Interceptor {
  static get name() {
    return "github-webhook";
  }

  static attributes = prepareAttributesDefinitions(
    {
      secret: {
        ...secret_attribute,
        description: "secret to authorize request"
      }
    },
    Interceptor.attributes
  );

  async receive(endpoint, next, ctx) {
    const [sig, event, id] = headers(ctx, [
      "x-hub-signature",
      "x-github-event",
      "x-github-delivery"
    ]);

    if (!sig) {
      ctx.throw(401, "x-hub-signature is missing");
    }

    const body = await rawBody(ctx.req);

    if (!verify(sig, body, this.secret)) {
      ctx.throw(403, "x-hub-signature does not match blob signature");
    }

    const response = await next(JSON.parse(body.toString()), event);

    ctx.res.writeHead(200, RESPONSE_HEADERS);
    ctx.res.end(JSON.stringify(response));
  }
}

/**
 *
 */
export class GiteaHookInterceptor extends Interceptor {
  static get name() {
    return "gitea-webhook";
  }

  async receive(endpoint, next, ctx) {
    const [event, id] = headers(ctx, ["x-gitea-event", "x-gitea-delivery"]);

    const body = await rawBody(ctx.req);
    const data = JSON.parse(body.toString());

    if (this.secret !== data.secret) {
      ctx.throw(401, "incorrect credentials");
    }

    if (!verify(sig, body, this.secret)) {
      ctx.throw(403, "x-hub-signature does not match blob signature");
    }

    const response = await next(data, event);

    ctx.res.writeHead(200, RESPONSE_HEADERS);
    ctx.res.end(JSON.stringify(response));
  }
}

/**
 *
 */
export class BitbucketHookInterceptor extends Interceptor {
  static get name() {
    return "bitbucket-webhook";
  }

  async receive(endpoint, next, ctx) {
    const [event] = headers(ctx, ["x-event-key"]);
    const body = await rawBody(ctx.req);
    const data = JSON.parse(body.toString());

    const response = await next(data, event);

    ctx.res.writeHead(200, RESPONSE_HEADERS);

    ctx.res.end(JSON.stringify(response));
  }
}

function headers(ctx, names) {
  return names.map(name => {
    const v = ctx.req.headers[name];
    if (v === undefined || v.length === 0) {
      ctx.throw(400, `${name} required`);
    }
    return v;
  });
}

export function sign(data, secret) {
  return "sha1=" + createHmac("sha1", secret).update(data).digest("hex");
}

function verify(signature, data, secret) {
  return Buffer.from(signature).equals(Buffer.from(sign(data, secret)));
}

async function rawBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
  }
  return chunks.join("");
}

const RESPONSE_HEADERS = {
  "content-type": "application/json"
};
