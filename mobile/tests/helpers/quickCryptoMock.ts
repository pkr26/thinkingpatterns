/**
 * react-native-quick-crypto mock (vitest alias): the real module is a native
 * addon that only loads on a device. node:crypto implements the same API
 * surface the app touches (randomBytes), keeping the shipping code paths
 * honest without a native runtime.
 */
import nodeCrypto from "node:crypto";

const qcrypto = nodeCrypto as typeof nodeCrypto;

export default qcrypto;
export const randomBytes = nodeCrypto.randomBytes;
