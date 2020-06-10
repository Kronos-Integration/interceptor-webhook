import { createHmac } from "crypto";
import { Interceptor } from '@kronos-integration/interceptor';



/**
 *
 */
export class GithubHookInterceptor extends Interceptor {
  static get name() {
    return 'github-webhook';
  }

  async receive(endpoint, next, request) {
    const [sig, event, id] = headers(request, [
      "x-hub-signature",
      "x-github-event",
      "x-github-delivery"
    ]);

    const body = await rawBody(ctx.req);

    if (!verify(sig, body, this.secret)) {
      throw("x-hub-signature does not match blob signature");
    }

    return next(JSON.parse(body.toString()), event);
  }
}


export class GiteaHookInterceptor extends Interceptor {
  static get name() {
    return 'gitea-webhook';
  }

  async receive(endpoint, next, request) {
    const [event, id] = headers(request, ["x-gitea-event", "x-gitea-delivery"]);

    const body = await rawBody(ctx.req);
    const data = JSON.parse(body.toString());

    if (this.secret !== data.secret) {
      throw "incorrect credentials";
    }

    if (!verify(sig, body, this.secret)) {
      throw "x-hub-signature does not match blob signature";
    }

    return next(data, event);
  }
}


export class BitbucketHookInterceptor extends Interceptor {
  static get name() {
    return 'bitbucket-webhook';
  }

  async receive(endpoint, next, request) {
    const [event] = headers(request, ["X-Event-Key"]);

    const body = await rawBody(ctx.req);
    const data = JSON.parse(body.toString());

    return next(data, event);
  }
}

function headers(ctx, names) {
  return names.map(name => {
    const v = ctx.get(name);
    if (v === undefined || v.length === 0) {
      ctx.throw(400, `${name} required`);
    }
    return v;
  });
}

function sign(data, secret) {
  return (
    "sha1=" +
    createHmac("sha1", secret)
      .update(data)
      .digest("hex")
  );
}

function verify(signature, data, secret) {
  return Buffer.from(signature).equals(Buffer.from(sign(data, secret)));
}
