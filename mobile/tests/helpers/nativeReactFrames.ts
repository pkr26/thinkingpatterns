import {createRequire} from "node:module";
import {readFileSync} from "node:fs";

/** Actual React19.2.3 reconciler; the scheduler transport exposes its commit
 * and passive-work boundaries. Native Fabric uses the same prior-effect
 * flush ordering, schedules passive work at NormalPriority, and actual
 * EventBeat schedules input/navigation delivery at ImmediatePriority.
 * This is a screen/React frame integration contract, without a UIKit claim. */
const requireReact=createRequire(import.meta.url);
export const nativeFrameScheduler=requireReact("scheduler/unstable_mock");
const rendererModule={exports:{} as typeof import("react-test-renderer")};
new Function("require","module","exports",readFileSync(requireReact.resolve("react-test-renderer/cjs/react-test-renderer.development.js"),"utf8"))(
 (name:string)=>name==="scheduler"||name==="scheduler/unstable_mock"?nativeFrameScheduler:requireReact(name),
 rendererModule,rendererModule.exports,
);
export const nativeFrameRenderer=rendererModule.exports;
