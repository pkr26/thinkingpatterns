import {defineConfig} from 'vitest/config';
import base from './vitest.config';
export default defineConfig({...base,cacheDir:process.env.HISTORY_PAGING_TASK_CACHE,test:{...base.test,include:['tests/historyPagingAdmission.task.tsx'],pool:'forks',maxWorkers:1,fileParallelism:false,cache:false,testTimeout:10000}});
