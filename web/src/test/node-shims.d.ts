// Minimal typings for the Node built-ins used by the unit tests (avoids a dependency on @types/node).
declare module "node:test" {
  type Fn = (t: unknown) => void | Promise<void>;
  export function test(name: string, fn: Fn): Promise<void>;
  export function describe(name: string, fn: () => void): void;
  export const it: typeof test;
}

declare module "node:assert/strict" {
  interface Assert {
    (value: unknown, message?: string): asserts value;
    ok(value: unknown, message?: string): asserts value;
    equal<T>(actual: unknown, expected: T, message?: string): asserts actual is T;
    notEqual(actual: unknown, expected: unknown, message?: string): void;
    deepEqual<T>(actual: unknown, expected: T, message?: string): asserts actual is T;
    throws(fn: () => unknown, message?: string): void;
    rejects(
      p: Promise<unknown> | (() => Promise<unknown>),
      expected?: string | RegExp | ((e: unknown) => boolean),
      message?: string,
    ): Promise<void>;
    match(value: string, re: RegExp, message?: string): void;
  }
  const assert: Assert;
  export default assert;
}
