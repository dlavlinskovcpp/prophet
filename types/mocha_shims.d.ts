declare function describe(name: string, fn: () => void): void;
declare function it(name: string, fn: () => Promise<void> | void): void;
declare function before(fn: () => Promise<void> | void): void;
declare function after(fn: () => Promise<void> | void): void;
declare function beforeEach(fn: () => Promise<void> | void): void;
declare function afterEach(fn: () => Promise<void> | void): void;

declare module "chai" {
  export const assert: any;
}

declare module "tweetnacl" {
  const nacl: any;
  export = nacl;
}
