import test from "ava";
import { TestContext } from "./helpers/context.mjs";
import { SendEndpoint } from "@kronos-integration/endpoint";

test("ic", async t => {
  const endpoint = new SendEndpoint("e", {});
  const interceptor = new CTXJWTVerifyInterceptor();

  const ctx = new TestContext({
    headers: { authorization: "Bearer 1234" }
  });

  await interceptor.receive(endpoint, (ctx, a, b, c) => {}, ctx, 1, 2, 3);

  t.is(ctx.code, 401);
});
