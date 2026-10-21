import base from "./vitest.config";
const cacheDir=process.env.FRONTEND_NATIVE_GC_CACHE_DIR;
if(!cacheDir)throw new Error("SetupError: use the owned tools/run-native-gc.mjs command for private GC receipts/cache");
export default {...base,cacheDir,test:{...base.test,cache:false,update:"none",include:["tests/frontendSettledSlotRetention.gc.ts"],pool:"forks",execArgv:["--expose-gc"],maxWorkers:1,fileParallelism:false,testTimeout:120000,hookTimeout:120000,coverage:{...base.test?.coverage,enabled:false}}};
