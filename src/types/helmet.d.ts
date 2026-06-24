// Type declarations for helmet (v7+ ships .d.cts but without default export,
// causing `import helmet from "helmet"` to fail under CommonJS + esModuleInterop
// in some configurations). This shim uses `any` for the options object —
// the runtime API is well-tested; we only need TypeScript to accept the call.
declare module "helmet" {
    import {RequestHandler} from "express";

    interface HelmetOptions {
        [key: string]: any;
    }

    function helmet(options?: HelmetOptions): RequestHandler;

    export = helmet;
}