// src/index.ts
import { createServer } from "http";
import { readFileSync as readFileSync10, writeFileSync as writeFileSync8 } from "fs";

// ../secret-store/dist/index.js
import { randomBytes, createCipheriv, createDecipheriv } from "crypto";

// ../../node_modules/.pnpm/hash-wasm@4.12.0/node_modules/hash-wasm/dist/index.esm.js
function __awaiter(thisArg, _arguments, P, generator) {
  function adopt(value) {
    return value instanceof P ? value : new P(function(resolve) {
      resolve(value);
    });
  }
  return new (P || (P = Promise))(function(resolve, reject) {
    function fulfilled(value) {
      try {
        step(generator.next(value));
      } catch (e) {
        reject(e);
      }
    }
    function rejected(value) {
      try {
        step(generator["throw"](value));
      } catch (e) {
        reject(e);
      }
    }
    function step(result) {
      result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected);
    }
    step((generator = generator.apply(thisArg, _arguments || [])).next());
  });
}
var Mutex = class {
  constructor() {
    this.mutex = Promise.resolve();
  }
  lock() {
    let begin = () => {
    };
    this.mutex = this.mutex.then(() => new Promise(begin));
    return new Promise((res) => {
      begin = res;
    });
  }
  dispatch(fn) {
    return __awaiter(this, void 0, void 0, function* () {
      const unlock = yield this.lock();
      try {
        return yield Promise.resolve(fn());
      } finally {
        unlock();
      }
    });
  }
};
var _a;
function getGlobal() {
  if (typeof globalThis !== "undefined")
    return globalThis;
  if (typeof self !== "undefined")
    return self;
  if (typeof window !== "undefined")
    return window;
  return global;
}
var globalObject = getGlobal();
var nodeBuffer = (_a = globalObject.Buffer) !== null && _a !== void 0 ? _a : null;
var textEncoder = globalObject.TextEncoder ? new globalObject.TextEncoder() : null;
function hexCharCodesToInt(a, b) {
  return (a & 15) + (a >> 6 | a >> 3 & 8) << 4 | (b & 15) + (b >> 6 | b >> 3 & 8);
}
function writeHexToUInt8(buf, str3) {
  const size = str3.length >> 1;
  for (let i = 0; i < size; i++) {
    const index = i << 1;
    buf[i] = hexCharCodesToInt(str3.charCodeAt(index), str3.charCodeAt(index + 1));
  }
}
function hexStringEqualsUInt8(str3, buf) {
  if (str3.length !== buf.length * 2) {
    return false;
  }
  for (let i = 0; i < buf.length; i++) {
    const strIndex = i << 1;
    if (buf[i] !== hexCharCodesToInt(str3.charCodeAt(strIndex), str3.charCodeAt(strIndex + 1))) {
      return false;
    }
  }
  return true;
}
var alpha = "a".charCodeAt(0) - 10;
var digit = "0".charCodeAt(0);
function getDigestHex(tmpBuffer, input, hashLength) {
  let p = 0;
  for (let i = 0; i < hashLength; i++) {
    let nibble = input[i] >>> 4;
    tmpBuffer[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
    nibble = input[i] & 15;
    tmpBuffer[p++] = nibble > 9 ? nibble + alpha : nibble + digit;
  }
  return String.fromCharCode.apply(null, tmpBuffer);
}
var getUInt8Buffer = nodeBuffer !== null ? (data) => {
  if (typeof data === "string") {
    const buf = nodeBuffer.from(data, "utf8");
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.length);
  }
  if (nodeBuffer.isBuffer(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.length);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new Error("Invalid data type!");
} : (data) => {
  if (typeof data === "string") {
    return textEncoder.encode(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  throw new Error("Invalid data type!");
};
var base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
var base64Lookup = new Uint8Array(256);
for (let i = 0; i < base64Chars.length; i++) {
  base64Lookup[base64Chars.charCodeAt(i)] = i;
}
function encodeBase64(data, pad = true) {
  const len = data.length;
  const extraBytes = len % 3;
  const parts = [];
  const len2 = len - extraBytes;
  for (let i = 0; i < len2; i += 3) {
    const tmp = (data[i] << 16 & 16711680) + (data[i + 1] << 8 & 65280) + (data[i + 2] & 255);
    const triplet = base64Chars.charAt(tmp >> 18 & 63) + base64Chars.charAt(tmp >> 12 & 63) + base64Chars.charAt(tmp >> 6 & 63) + base64Chars.charAt(tmp & 63);
    parts.push(triplet);
  }
  if (extraBytes === 1) {
    const tmp = data[len - 1];
    const a = base64Chars.charAt(tmp >> 2);
    const b = base64Chars.charAt(tmp << 4 & 63);
    parts.push(`${a}${b}`);
    if (pad) {
      parts.push("==");
    }
  } else if (extraBytes === 2) {
    const tmp = (data[len - 2] << 8) + data[len - 1];
    const a = base64Chars.charAt(tmp >> 10);
    const b = base64Chars.charAt(tmp >> 4 & 63);
    const c = base64Chars.charAt(tmp << 2 & 63);
    parts.push(`${a}${b}${c}`);
    if (pad) {
      parts.push("=");
    }
  }
  return parts.join("");
}
function getDecodeBase64Length(data) {
  let bufferLength = Math.floor(data.length * 0.75);
  const len = data.length;
  if (data[len - 1] === "=") {
    bufferLength -= 1;
    if (data[len - 2] === "=") {
      bufferLength -= 1;
    }
  }
  return bufferLength;
}
function decodeBase64(data) {
  const bufferLength = getDecodeBase64Length(data);
  const len = data.length;
  const bytes = new Uint8Array(bufferLength);
  let p = 0;
  for (let i = 0; i < len; i += 4) {
    const encoded1 = base64Lookup[data.charCodeAt(i)];
    const encoded2 = base64Lookup[data.charCodeAt(i + 1)];
    const encoded3 = base64Lookup[data.charCodeAt(i + 2)];
    const encoded4 = base64Lookup[data.charCodeAt(i + 3)];
    bytes[p] = encoded1 << 2 | encoded2 >> 4;
    p += 1;
    bytes[p] = (encoded2 & 15) << 4 | encoded3 >> 2;
    p += 1;
    bytes[p] = (encoded3 & 3) << 6 | encoded4 & 63;
    p += 1;
  }
  return bytes;
}
var MAX_HEAP = 16 * 1024;
var WASM_FUNC_HASH_LENGTH = 4;
var wasmMutex = new Mutex();
var wasmModuleCache = /* @__PURE__ */ new Map();
function WASMInterface(binary, hashLength) {
  return __awaiter(this, void 0, void 0, function* () {
    let wasmInstance = null;
    let memoryView = null;
    let initialized = false;
    if (typeof WebAssembly === "undefined") {
      throw new Error("WebAssembly is not supported in this environment!");
    }
    const writeMemory = (data, offset = 0) => {
      memoryView.set(data, offset);
    };
    const getMemory = () => memoryView;
    const getExports = () => wasmInstance.exports;
    const setMemorySize = (totalSize) => {
      wasmInstance.exports.Hash_SetMemorySize(totalSize);
      const arrayOffset = wasmInstance.exports.Hash_GetBuffer();
      const memoryBuffer = wasmInstance.exports.memory.buffer;
      memoryView = new Uint8Array(memoryBuffer, arrayOffset, totalSize);
    };
    const getStateSize = () => {
      const view = new DataView(wasmInstance.exports.memory.buffer);
      const stateSize = view.getUint32(wasmInstance.exports.STATE_SIZE, true);
      return stateSize;
    };
    const loadWASMPromise = wasmMutex.dispatch(() => __awaiter(this, void 0, void 0, function* () {
      if (!wasmModuleCache.has(binary.name)) {
        const asm = decodeBase64(binary.data);
        const promise = WebAssembly.compile(asm);
        wasmModuleCache.set(binary.name, promise);
      }
      const module = yield wasmModuleCache.get(binary.name);
      wasmInstance = yield WebAssembly.instantiate(module, {
        // env: {
        //   emscripten_memcpy_big: (dest, src, num) => {
        //     const memoryBuffer = wasmInstance.exports.memory.buffer;
        //     const memView = new Uint8Array(memoryBuffer, 0);
        //     memView.set(memView.subarray(src, src + num), dest);
        //   },
        //   print_memory: (offset, len) => {
        //     const memoryBuffer = wasmInstance.exports.memory.buffer;
        //     const memView = new Uint8Array(memoryBuffer, 0);
        //     console.log('print_int32', memView.subarray(offset, offset + len));
        //   },
        // },
      });
    }));
    const setupInterface = () => __awaiter(this, void 0, void 0, function* () {
      if (!wasmInstance) {
        yield loadWASMPromise;
      }
      const arrayOffset = wasmInstance.exports.Hash_GetBuffer();
      const memoryBuffer = wasmInstance.exports.memory.buffer;
      memoryView = new Uint8Array(memoryBuffer, arrayOffset, MAX_HEAP);
    });
    const init = (bits = null) => {
      initialized = true;
      wasmInstance.exports.Hash_Init(bits);
    };
    const updateUInt8Array = (data) => {
      let read = 0;
      while (read < data.length) {
        const chunk = data.subarray(read, read + MAX_HEAP);
        read += chunk.length;
        memoryView.set(chunk);
        wasmInstance.exports.Hash_Update(chunk.length);
      }
    };
    const update = (data) => {
      if (!initialized) {
        throw new Error("update() called before init()");
      }
      const Uint8Buffer = getUInt8Buffer(data);
      updateUInt8Array(Uint8Buffer);
    };
    const digestChars = new Uint8Array(hashLength * 2);
    const digest = (outputType, padding = null) => {
      if (!initialized) {
        throw new Error("digest() called before init()");
      }
      initialized = false;
      wasmInstance.exports.Hash_Final(padding);
      if (outputType === "binary") {
        return memoryView.slice(0, hashLength);
      }
      return getDigestHex(digestChars, memoryView, hashLength);
    };
    const save = () => {
      if (!initialized) {
        throw new Error("save() can only be called after init() and before digest()");
      }
      const stateOffset = wasmInstance.exports.Hash_GetState();
      const stateLength = getStateSize();
      const memoryBuffer = wasmInstance.exports.memory.buffer;
      const internalState = new Uint8Array(memoryBuffer, stateOffset, stateLength);
      const prefixedState = new Uint8Array(WASM_FUNC_HASH_LENGTH + stateLength);
      writeHexToUInt8(prefixedState, binary.hash);
      prefixedState.set(internalState, WASM_FUNC_HASH_LENGTH);
      return prefixedState;
    };
    const load = (state) => {
      if (!(state instanceof Uint8Array)) {
        throw new Error("load() expects an Uint8Array generated by save()");
      }
      const stateOffset = wasmInstance.exports.Hash_GetState();
      const stateLength = getStateSize();
      const overallLength = WASM_FUNC_HASH_LENGTH + stateLength;
      const memoryBuffer = wasmInstance.exports.memory.buffer;
      if (state.length !== overallLength) {
        throw new Error(`Bad state length (expected ${overallLength} bytes, got ${state.length})`);
      }
      if (!hexStringEqualsUInt8(binary.hash, state.subarray(0, WASM_FUNC_HASH_LENGTH))) {
        throw new Error("This state was written by an incompatible hash implementation");
      }
      const internalState = state.subarray(WASM_FUNC_HASH_LENGTH);
      new Uint8Array(memoryBuffer, stateOffset, stateLength).set(internalState);
      initialized = true;
    };
    const isDataShort = (data) => {
      if (typeof data === "string") {
        return data.length < MAX_HEAP / 4;
      }
      return data.byteLength < MAX_HEAP;
    };
    let canSimplify = isDataShort;
    switch (binary.name) {
      case "argon2":
      case "scrypt":
        canSimplify = () => true;
        break;
      case "blake2b":
      case "blake2s":
        canSimplify = (data, initParam) => initParam <= 512 && isDataShort(data);
        break;
      case "blake3":
        canSimplify = (data, initParam) => initParam === 0 && isDataShort(data);
        break;
      case "xxhash64":
      // cannot simplify
      case "xxhash3":
      case "xxhash128":
      case "crc64":
        canSimplify = () => false;
        break;
    }
    const calculate = (data, initParam = null, digestParam = null) => {
      if (!canSimplify(data, initParam)) {
        init(initParam);
        update(data);
        return digest("hex", digestParam);
      }
      const buffer = getUInt8Buffer(data);
      memoryView.set(buffer);
      wasmInstance.exports.Hash_Calculate(buffer.length, initParam, digestParam);
      return getDigestHex(digestChars, memoryView, hashLength);
    };
    yield setupInterface();
    return {
      getMemory,
      writeMemory,
      getExports,
      setMemorySize,
      init,
      update,
      digest,
      save,
      load,
      calculate,
      hashLength
    };
  });
}
var mutex$l = new Mutex();
var name$k = "argon2";
var data$k = "AGFzbQEAAAABKQVgAX8Bf2AAAX9gEH9/f39/f39/f39/f39/f38AYAR/f39/AGACf38AAwYFAAECAwQFBgEBAoCAAgYIAX8BQZCoBAsHQQQGbWVtb3J5AgASSGFzaF9TZXRNZW1vcnlTaXplAAAOSGFzaF9HZXRCdWZmZXIAAQ5IYXNoX0NhbGN1bGF0ZQAECvEyBVgBAn9BACEBAkAgAEEAKAKICCICRg0AAkAgACACayIAQRB2IABBgIB8cSAASWoiAEAAQX9HDQBB/wHADwtBACEBQQBBACkDiAggAEEQdK18NwOICAsgAcALcAECfwJAQQAoAoAIIgANAEEAPwBBEHQiADYCgAhBACgCiAgiAUGAgCBGDQACQEGAgCAgAWsiAEEQdiAAQYCAfHEgAElqIgBAAEF/Rw0AQQAPC0EAQQApA4gIIABBEHStfDcDiAhBACgCgAghAAsgAAvcDgECfiAAIAQpAwAiECAAKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAMIBAgDCkDAIVCIIkiEDcDACAIIBAgCCkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgBCAQIAQpAwCFQiiJIhA3AwAgACAQIAApAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIAwgECAMKQMAhUIwiSIQNwMAIAggECAIKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAEIBAgBCkDAIVCAYk3AwAgASAFKQMAIhAgASkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgDSAQIA0pAwCFQiCJIhA3AwAgCSAQIAkpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAUgECAFKQMAhUIoiSIQNwMAIAEgECABKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACANIBAgDSkDAIVCMIkiEDcDACAJIBAgCSkDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgBSAQIAUpAwCFQgGJNwMAIAIgBikDACIQIAIpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIA4gECAOKQMAhUIgiSIQNwMAIAogECAKKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAGIBAgBikDAIVCKIkiEDcDACACIBAgAikDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgDiAQIA4pAwCFQjCJIhA3AwAgCiAQIAopAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIAYgECAGKQMAhUIBiTcDACADIAcpAwAiECADKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAPIBAgDykDAIVCIIkiEDcDACALIBAgCykDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgByAQIAcpAwCFQiiJIhA3AwAgAyAQIAMpAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIA8gECAPKQMAhUIwiSIQNwMAIAsgECALKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAHIBAgBykDAIVCAYk3AwAgACAFKQMAIhAgACkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgDyAQIA8pAwCFQiCJIhA3AwAgCiAQIAopAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAUgECAFKQMAhUIoiSIQNwMAIAAgECAAKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAPIBAgDykDAIVCMIkiEDcDACAKIBAgCikDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgBSAQIAUpAwCFQgGJNwMAIAEgBikDACIQIAEpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAwgECAMKQMAhUIgiSIQNwMAIAsgECALKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACAGIBAgBikDAIVCKIkiEDcDACABIBAgASkDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgDCAQIAwpAwCFQjCJIhA3AwAgCyAQIAspAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIAYgECAGKQMAhUIBiTcDACACIAcpAwAiECACKQMAIhF8IBFCAYZC/v///x+DIBBC/////w+DfnwiEDcDACANIBAgDSkDAIVCIIkiEDcDACAIIBAgCCkDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgByAQIAcpAwCFQiiJIhA3AwAgAiAQIAIpAwAiEXwgEEL/////D4MgEUIBhkL+////H4N+fCIQNwMAIA0gECANKQMAhUIwiSIQNwMAIAggECAIKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAHIBAgBykDAIVCAYk3AwAgAyAEKQMAIhAgAykDACIRfCARQgGGQv7///8fgyAQQv////8Pg358IhA3AwAgDiAQIA4pAwCFQiCJIhA3AwAgCSAQIAkpAwAiEXwgEUIBhkL+////H4MgEEL/////D4N+fCIQNwMAIAQgECAEKQMAhUIoiSIQNwMAIAMgECADKQMAIhF8IBBC/////w+DIBFCAYZC/v///x+DfnwiEDcDACAOIBAgDikDAIVCMIkiEDcDACAJIBAgCSkDACIRfCAQQv////8PgyARQgGGQv7///8fg358IhA3AwAgBCAQIAQpAwCFQgGJNwMAC98aAQN/QQAhBEEAIAIpAwAgASkDAIU3A5AIQQAgAikDCCABKQMIhTcDmAhBACACKQMQIAEpAxCFNwOgCEEAIAIpAxggASkDGIU3A6gIQQAgAikDICABKQMghTcDsAhBACACKQMoIAEpAyiFNwO4CEEAIAIpAzAgASkDMIU3A8AIQQAgAikDOCABKQM4hTcDyAhBACACKQNAIAEpA0CFNwPQCEEAIAIpA0ggASkDSIU3A9gIQQAgAikDUCABKQNQhTcD4AhBACACKQNYIAEpA1iFNwPoCEEAIAIpA2AgASkDYIU3A/AIQQAgAikDaCABKQNohTcD+AhBACACKQNwIAEpA3CFNwOACUEAIAIpA3ggASkDeIU3A4gJQQAgAikDgAEgASkDgAGFNwOQCUEAIAIpA4gBIAEpA4gBhTcDmAlBACACKQOQASABKQOQAYU3A6AJQQAgAikDmAEgASkDmAGFNwOoCUEAIAIpA6ABIAEpA6ABhTcDsAlBACACKQOoASABKQOoAYU3A7gJQQAgAikDsAEgASkDsAGFNwPACUEAIAIpA7gBIAEpA7gBhTcDyAlBACACKQPAASABKQPAAYU3A9AJQQAgAikDyAEgASkD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";
var hash$k = "e4cdc523";
var wasmJson$k = {
  name: name$k,
  data: data$k,
  hash: hash$k
};
var name$j = "blake2b";
var data$j = "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";
var hash$j = "c6f286e6";
var wasmJson$j = {
  name: name$j,
  data: data$j,
  hash: hash$j
};
var mutex$k = new Mutex();
function validateBits$4(bits) {
  if (!Number.isInteger(bits) || bits < 8 || bits > 512 || bits % 8 !== 0) {
    return new Error("Invalid variant! Valid values: 8, 16, ..., 512");
  }
  return null;
}
function getInitParam$1(outputBits, keyBits) {
  return outputBits | keyBits << 16;
}
function createBLAKE2b(bits = 512, key = null) {
  if (validateBits$4(bits)) {
    return Promise.reject(validateBits$4(bits));
  }
  let keyBuffer = null;
  let initParam = bits;
  if (key !== null) {
    keyBuffer = getUInt8Buffer(key);
    if (keyBuffer.length > 64) {
      return Promise.reject(new Error("Max key length is 64 bytes"));
    }
    initParam = getInitParam$1(bits, keyBuffer.length);
  }
  const outputSize = bits / 8;
  return WASMInterface(wasmJson$j, outputSize).then((wasm) => {
    if (initParam > 512) {
      wasm.writeMemory(keyBuffer);
    }
    wasm.init(initParam);
    const obj = {
      init: initParam > 512 ? () => {
        wasm.writeMemory(keyBuffer);
        wasm.init(initParam);
        return obj;
      } : () => {
        wasm.init(initParam);
        return obj;
      },
      update: (data) => {
        wasm.update(data);
        return obj;
      },
      // biome-ignore lint/suspicious/noExplicitAny: Conflict with IHasher type
      digest: (outputType) => wasm.digest(outputType),
      save: () => wasm.save(),
      load: (data) => {
        wasm.load(data);
        return obj;
      },
      blockSize: 128,
      digestSize: outputSize
    };
    return obj;
  });
}
function encodeResult(salt, options, res) {
  const parameters = [
    `m=${options.memorySize}`,
    `t=${options.iterations}`,
    `p=${options.parallelism}`
  ].join(",");
  return `$argon2${options.hashType}$v=19$${parameters}$${encodeBase64(salt, false)}$${encodeBase64(res, false)}`;
}
var uint32View = new DataView(new ArrayBuffer(4));
function int32LE(x) {
  uint32View.setInt32(0, x, true);
  return new Uint8Array(uint32View.buffer);
}
function hashFunc(blake512, buf, len) {
  return __awaiter(this, void 0, void 0, function* () {
    if (len <= 64) {
      const blake = yield createBLAKE2b(len * 8);
      blake.update(int32LE(len));
      blake.update(buf);
      return blake.digest("binary");
    }
    const r = Math.ceil(len / 32) - 2;
    const ret = new Uint8Array(len);
    blake512.init();
    blake512.update(int32LE(len));
    blake512.update(buf);
    let vp = blake512.digest("binary");
    ret.set(vp.subarray(0, 32), 0);
    for (let i = 1; i < r; i++) {
      blake512.init();
      blake512.update(vp);
      vp = blake512.digest("binary");
      ret.set(vp.subarray(0, 32), i * 32);
    }
    const partialBytesNeeded = len - 32 * r;
    let blakeSmall;
    if (partialBytesNeeded === 64) {
      blakeSmall = blake512;
      blakeSmall.init();
    } else {
      blakeSmall = yield createBLAKE2b(partialBytesNeeded * 8);
    }
    blakeSmall.update(vp);
    vp = blakeSmall.digest("binary");
    ret.set(vp.subarray(0, partialBytesNeeded), r * 32);
    return ret;
  });
}
function getHashType(type) {
  switch (type) {
    case "d":
      return 0;
    case "i":
      return 1;
    default:
      return 2;
  }
}
function argon2Internal(options) {
  return __awaiter(this, void 0, void 0, function* () {
    var _a2;
    const { parallelism, iterations, hashLength } = options;
    const password = getUInt8Buffer(options.password);
    const salt = getUInt8Buffer(options.salt);
    const version = 19;
    const hashType = getHashType(options.hashType);
    const { memorySize } = options;
    const secret = getUInt8Buffer((_a2 = options.secret) !== null && _a2 !== void 0 ? _a2 : "");
    const [argon2Interface, blake512] = yield Promise.all([
      WASMInterface(wasmJson$k, 1024),
      createBLAKE2b(512)
    ]);
    argon2Interface.setMemorySize(memorySize * 1024 + 1024);
    const initVector = new Uint8Array(24);
    const initVectorView = new DataView(initVector.buffer);
    initVectorView.setInt32(0, parallelism, true);
    initVectorView.setInt32(4, hashLength, true);
    initVectorView.setInt32(8, memorySize, true);
    initVectorView.setInt32(12, iterations, true);
    initVectorView.setInt32(16, version, true);
    initVectorView.setInt32(20, hashType, true);
    argon2Interface.writeMemory(initVector, memorySize * 1024);
    blake512.init();
    blake512.update(initVector);
    blake512.update(int32LE(password.length));
    blake512.update(password);
    blake512.update(int32LE(salt.length));
    blake512.update(salt);
    blake512.update(int32LE(secret.length));
    blake512.update(secret);
    blake512.update(int32LE(0));
    const segments = Math.floor(memorySize / (parallelism * 4));
    const lanes = segments * 4;
    const param = new Uint8Array(72);
    const H0 = blake512.digest("binary");
    param.set(H0);
    for (let lane = 0; lane < parallelism; lane++) {
      param.set(int32LE(0), 64);
      param.set(int32LE(lane), 68);
      let position = lane * lanes;
      let chunk = yield hashFunc(blake512, param, 1024);
      argon2Interface.writeMemory(chunk, position * 1024);
      position += 1;
      param.set(int32LE(1), 64);
      chunk = yield hashFunc(blake512, param, 1024);
      argon2Interface.writeMemory(chunk, position * 1024);
    }
    const C = new Uint8Array(1024);
    writeHexToUInt8(C, argon2Interface.calculate(new Uint8Array([]), memorySize));
    const res = yield hashFunc(blake512, C, hashLength);
    if (options.outputType === "hex") {
      const digestChars = new Uint8Array(hashLength * 2);
      return getDigestHex(digestChars, res, hashLength);
    }
    if (options.outputType === "encoded") {
      return encodeResult(salt, options, res);
    }
    return res;
  });
}
var validateOptions$3 = (options) => {
  var _a2;
  if (!options || typeof options !== "object") {
    throw new Error("Invalid options parameter. It requires an object.");
  }
  if (!options.password) {
    throw new Error("Password must be specified");
  }
  options.password = getUInt8Buffer(options.password);
  if (options.password.length < 1) {
    throw new Error("Password must be specified");
  }
  if (!options.salt) {
    throw new Error("Salt must be specified");
  }
  options.salt = getUInt8Buffer(options.salt);
  if (options.salt.length < 8) {
    throw new Error("Salt should be at least 8 bytes long");
  }
  options.secret = getUInt8Buffer((_a2 = options.secret) !== null && _a2 !== void 0 ? _a2 : "");
  if (!Number.isInteger(options.iterations) || options.iterations < 1) {
    throw new Error("Iterations should be a positive number");
  }
  if (!Number.isInteger(options.parallelism) || options.parallelism < 1) {
    throw new Error("Parallelism should be a positive number");
  }
  if (!Number.isInteger(options.hashLength) || options.hashLength < 4) {
    throw new Error("Hash length should be at least 4 bytes.");
  }
  if (!Number.isInteger(options.memorySize)) {
    throw new Error("Memory size should be specified.");
  }
  if (options.memorySize < 8 * options.parallelism) {
    throw new Error("Memory size should be at least 8 * parallelism.");
  }
  if (options.outputType === void 0) {
    options.outputType = "hex";
  }
  if (!["hex", "binary", "encoded"].includes(options.outputType)) {
    throw new Error(`Insupported output type ${options.outputType}. Valid values: ['hex', 'binary', 'encoded']`);
  }
};
function argon2id(options) {
  return __awaiter(this, void 0, void 0, function* () {
    validateOptions$3(options);
    return argon2Internal(Object.assign(Object.assign({}, options), { hashType: "id" }));
  });
}
var mutex$j = new Mutex();
var mutex$i = new Mutex();
var mutex$h = new Mutex();
var mutex$g = new Mutex();
var polyBuffer = new Uint8Array(8);
var mutex$f = new Mutex();
var mutex$e = new Mutex();
var mutex$d = new Mutex();
var mutex$c = new Mutex();
var mutex$b = new Mutex();
var mutex$a = new Mutex();
var mutex$9 = new Mutex();
var mutex$8 = new Mutex();
var mutex$7 = new Mutex();
var mutex$6 = new Mutex();
var mutex$5 = new Mutex();
var seedBuffer$2 = new Uint8Array(8);
var mutex$4 = new Mutex();
var seedBuffer$1 = new Uint8Array(8);
var mutex$3 = new Mutex();
var seedBuffer = new Uint8Array(8);
var mutex$2 = new Mutex();
var mutex$1 = new Mutex();
var mutex = new Mutex();

// ../secret-store/dist/index.js
var ALG = "AES-256-GCM";
var KEY_BYTES = 32;
var NONCE_BYTES = 12;
var SALT_BYTES = 16;
var TAG_BYTES = 16;
var ARGON2 = {
  parallelism: 1,
  iterations: 3,
  memorySize: 65536
  /* KiB = 64 MiB */
};
var b64 = (b) => Buffer.from(b).toString("base64");
var unb64 = (s) => Buffer.from(s, "base64");
function generateBoxKey() {
  return b64(randomBytes(KEY_BYTES));
}
function generateSalt() {
  return b64(randomBytes(SALT_BYTES));
}
async function deriveUserKey(masterPassword, saltB64) {
  const hex = await argon2id({
    password: masterPassword,
    salt: unb64(saltB64),
    ...ARGON2,
    hashLength: KEY_BYTES,
    outputType: "hex"
  });
  return Buffer.from(hex, "hex");
}
function aad(ids2, version) {
  return Buffer.from(`${ids2.orgId}:${ids2.boxId}:${version}`, "utf8");
}
function encrypt(plaintext, key, ad) {
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(ad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag2 = cipher.getAuthTag();
  return { nonce: b64(nonce), ct: b64(Buffer.concat([ct, tag2])) };
}
function decrypt(payload, key, ad) {
  const raw = unb64(payload.ct);
  const ct = raw.subarray(0, raw.length - TAG_BYTES);
  const tag2 = raw.subarray(raw.length - TAG_BYTES);
  const decipher = createDecipheriv("aes-256-gcm", key, unb64(payload.nonce));
  decipher.setAAD(ad);
  decipher.setAuthTag(tag2);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}
async function seal(plaintext, opts) {
  const salt = opts.salt ?? generateSalt();
  const ad = aad(opts.ids, opts.version);
  const pt = Buffer.from(plaintext, "utf8");
  const userKey = await deriveUserKey(opts.masterPassword, salt);
  return {
    alg: ALG,
    version: opts.version,
    salt,
    payload_box: encrypt(pt, unb64(opts.boxKey), ad),
    payload_user: encrypt(pt, userKey, ad)
  };
}
function openWithBoxKey(record, boxKey, ids2) {
  return decrypt(record.payload_box, unb64(boxKey), aad(ids2, record.version)).toString("utf8");
}
async function openWithUserKey(record, masterPassword, ids2) {
  const userKey = await deriveUserKey(masterPassword, record.salt);
  return decrypt(record.payload_user, userKey, aad(ids2, record.version)).toString("utf8");
}
async function migrateToNewBox(args) {
  const { source, masterPassword, sourceIds, newBoxId } = args;
  const plaintext = await openWithUserKey(source, masterPassword, sourceIds);
  const boxKey = generateBoxKey();
  const ids2 = { orgId: sourceIds.orgId, boxId: newBoxId };
  const record = await seal(plaintext, {
    boxKey,
    masterPassword,
    ids: ids2,
    version: source.version + 1,
    // Keep the same password salt so the user key is stable across boxes.
    salt: source.salt
  });
  return { record, boxKey };
}

// src/box-key.ts
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "fs";
import { dirname } from "path";
function loadOrCreateBoxKey(path) {
  if (existsSync(path)) {
    return readFileSync(path, "utf8").trim();
  }
  const key = generateBoxKey();
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, key, { mode: 384 });
  console.log(`[box-key] generated new box key at ${path}`);
  return key;
}

// src/keys.ts
import crypto2 from "crypto";
import { readFileSync as readFileSync2, writeFileSync as writeFileSync2, existsSync as existsSync2, mkdirSync as mkdirSync2 } from "fs";
function readFile(path) {
  try {
    return readFileSync2(path, "utf8").trim();
  } catch {
    return null;
  }
}
function ensureVmKeypair(keysDir) {
  const privPath = `${keysDir}/vm_private_key.pem`;
  const pubPath = `${keysDir}/vm_public_key.pem`;
  if (existsSync2(privPath)) {
    return readFile(pubPath) ?? derivePublicKey(readFileSync2(privPath, "utf8"));
  }
  const { publicKey, privateKey } = crypto2.generateKeyPairSync("ed25519", {
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" }
  });
  mkdirSync2(keysDir, { recursive: true });
  writeFileSync2(privPath, privateKey, { mode: 384 });
  writeFileSync2(pubPath, publicKey, { mode: 420 });
  console.log("[keys] generated on-box vm keypair");
  return publicKey;
}
function derivePublicKey(privatePem) {
  const pub = crypto2.createPublicKey(privatePem);
  return pub.export({ type: "spki", format: "pem" }).toString();
}
var sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function registerPublicKey(keysDir) {
  const vmId = readFile(`${keysDir}/vm_id`);
  const token = readFile(`${keysDir}/bootstrap_token`);
  const registerUrl = readFile(`${keysDir}/register_api_url`);
  const publicKey = readFile(`${keysDir}/vm_public_key.pem`);
  if (!token || !registerUrl) return;
  if (!vmId || !publicKey) {
    console.warn("[keys] missing vm_id / vm_public_key.pem \u2014 cannot register");
    return;
  }
  const maxAttempts = 10;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const res = await fetch(registerUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "content-type": "application/json" },
        body: JSON.stringify({ vm_id: vmId, public_key: publicKey })
      });
      if (res.ok) {
        console.log(`[keys] registered public key (attempt ${attempt})`);
        return;
      }
      if (res.status === 409) {
        console.error("[keys] registration refused (409): identity already registered to another key");
        return;
      }
      console.warn(`[keys] register attempt ${attempt}/${maxAttempts}: HTTP ${res.status}`);
    } catch (err) {
      console.warn(`[keys] register attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
    }
    await sleep(Math.min(2e3 * attempt, 15e3));
  }
  console.error(`[keys] gave up registering after ${maxAttempts} attempts`);
}
function signDetached(keysDir, message2) {
  const privatePem = readFileSync2(`${keysDir}/vm_private_key.pem`, "utf8");
  const key = crypto2.createPrivateKey(privatePem);
  return crypto2.sign(null, Buffer.from(message2, "utf8"), key).toString("base64");
}

// src/store-client.ts
import { readFileSync as readFileSync3, writeFileSync as writeFileSync3, existsSync as existsSync3 } from "fs";
function makeStoreClient(url, getToken2) {
  if (url.startsWith("file:")) {
    const path = url.replace(/^file:(\/\/)?/, "");
    return {
      async fetchRecord() {
        if (!existsSync3(path)) return null;
        return JSON.parse(readFileSync3(path, "utf8"));
      },
      async putRecord(record) {
        writeFileSync3(path, JSON.stringify(record), { mode: 384 });
      }
    };
  }
  const headers = async () => getToken2 ? { Authorization: `Bearer ${await getToken2()}` } : {};
  return makeHttpClient(url, headers);
}
function makeHttpClient(url, headers) {
  return {
    async fetchRecord() {
      const res = await fetch(url, { headers: await headers() });
      if (res.status === 404) return null;
      if (!res.ok) throw new Error(`store GET failed: ${res.status}`);
      return await res.json();
    },
    async putRecord(record) {
      const res = await fetch(url, {
        method: "POST",
        headers: { ...await headers(), "content-type": "application/json" },
        body: JSON.stringify(record)
      });
      if (!res.ok) throw new Error(`store POST failed: ${res.status}`);
    }
  };
}
async function fetchList(url, key, getToken2) {
  if (url.startsWith("file:")) {
    const path = url.replace(/^file:(\/\/)?/, "");
    if (!existsSync3(path)) return [];
    const parsed = JSON.parse(readFileSync3(path, "utf8"));
    if (Array.isArray(parsed)) return parsed;
    return parsed[key] ?? [];
  }
  const res = await fetch(url, {
    headers: getToken2 ? { Authorization: `Bearer ${await getToken2()}` } : {}
  });
  if (!res.ok) throw new Error(`${key} GET failed: ${res.status}`);
  const body = await res.json();
  return body[key] ?? [];
}
function fetchRules(url, getToken2) {
  return fetchList(url, "rules", getToken2);
}
function fetchIdentities(url, getToken2) {
  return fetchList(url, "identities", getToken2);
}

// src/box-token.ts
import { readFileSync as readFileSync4 } from "fs";

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/buffer_utils.js
var encoder = new TextEncoder();
var decoder = new TextDecoder();
var MAX_INT32 = 2 ** 32;
function concat(...buffers) {
  const size = buffers.reduce((acc, { length }) => acc + length, 0);
  const buf = new Uint8Array(size);
  let i = 0;
  for (const buffer of buffers) {
    buf.set(buffer, i);
    i += buffer.length;
  }
  return buf;
}
function encode(string) {
  const bytes = new Uint8Array(string.length);
  for (let i = 0; i < string.length; i++) {
    const code = string.charCodeAt(i);
    if (code > 127) {
      throw new TypeError("non-ASCII string encountered in encode()");
    }
    bytes[i] = code;
  }
  return bytes;
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/base64.js
function encodeBase642(input) {
  if (Uint8Array.prototype.toBase64) {
    return input.toBase64();
  }
  const CHUNK_SIZE = 32768;
  const arr = [];
  for (let i = 0; i < input.length; i += CHUNK_SIZE) {
    arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)));
  }
  return btoa(arr.join(""));
}
function decodeBase642(encoded) {
  if (Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(encoded);
  }
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/util/base64url.js
function decode(input) {
  if (Uint8Array.fromBase64) {
    return Uint8Array.fromBase64(typeof input === "string" ? input : decoder.decode(input), {
      alphabet: "base64url"
    });
  }
  let encoded = input;
  if (encoded instanceof Uint8Array) {
    encoded = decoder.decode(encoded);
  }
  encoded = encoded.replace(/-/g, "+").replace(/_/g, "/");
  try {
    return decodeBase642(encoded);
  } catch {
    throw new TypeError("The input to be decoded is not correctly encoded.");
  }
}
function encode2(input) {
  let unencoded = input;
  if (typeof unencoded === "string") {
    unencoded = encoder.encode(unencoded);
  }
  if (Uint8Array.prototype.toBase64) {
    return unencoded.toBase64({ alphabet: "base64url", omitPadding: true });
  }
  return encodeBase642(unencoded).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/crypto_key.js
var unusable = (name, prop = "algorithm.name") => new TypeError(`CryptoKey does not support this operation, its ${prop} must be ${name}`);
var isAlgorithm = (algorithm, name) => algorithm.name === name;
function getHashLength(hash) {
  return parseInt(hash.name.slice(4), 10);
}
function checkHashLength(algorithm, expected) {
  const actual = getHashLength(algorithm.hash);
  if (actual !== expected)
    throw unusable(`SHA-${expected}`, "algorithm.hash");
}
function getNamedCurve(alg) {
  switch (alg) {
    case "ES256":
      return "P-256";
    case "ES384":
      return "P-384";
    case "ES512":
      return "P-521";
    default:
      throw new Error("unreachable");
  }
}
function checkUsage(key, usage) {
  if (usage && !key.usages.includes(usage)) {
    throw new TypeError(`CryptoKey does not support this operation, its usages must include ${usage}.`);
  }
}
function checkSigCryptoKey(key, alg, usage) {
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512": {
      if (!isAlgorithm(key.algorithm, "HMAC"))
        throw unusable("HMAC");
      checkHashLength(key.algorithm, parseInt(alg.slice(2), 10));
      break;
    }
    case "RS256":
    case "RS384":
    case "RS512": {
      if (!isAlgorithm(key.algorithm, "RSASSA-PKCS1-v1_5"))
        throw unusable("RSASSA-PKCS1-v1_5");
      checkHashLength(key.algorithm, parseInt(alg.slice(2), 10));
      break;
    }
    case "PS256":
    case "PS384":
    case "PS512": {
      if (!isAlgorithm(key.algorithm, "RSA-PSS"))
        throw unusable("RSA-PSS");
      checkHashLength(key.algorithm, parseInt(alg.slice(2), 10));
      break;
    }
    case "Ed25519":
    case "EdDSA": {
      if (!isAlgorithm(key.algorithm, "Ed25519"))
        throw unusable("Ed25519");
      break;
    }
    case "ML-DSA-44":
    case "ML-DSA-65":
    case "ML-DSA-87": {
      if (!isAlgorithm(key.algorithm, alg))
        throw unusable(alg);
      break;
    }
    case "ES256":
    case "ES384":
    case "ES512": {
      if (!isAlgorithm(key.algorithm, "ECDSA"))
        throw unusable("ECDSA");
      const expected = getNamedCurve(alg);
      const actual = key.algorithm.namedCurve;
      if (actual !== expected)
        throw unusable(expected, "algorithm.namedCurve");
      break;
    }
    default:
      throw new TypeError("CryptoKey does not support this operation");
  }
  checkUsage(key, usage);
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/invalid_key_input.js
function message(msg, actual, ...types) {
  types = types.filter(Boolean);
  if (types.length > 2) {
    const last = types.pop();
    msg += `one of type ${types.join(", ")}, or ${last}.`;
  } else if (types.length === 2) {
    msg += `one of type ${types[0]} or ${types[1]}.`;
  } else {
    msg += `of type ${types[0]}.`;
  }
  if (actual == null) {
    msg += ` Received ${actual}`;
  } else if (typeof actual === "function" && actual.name) {
    msg += ` Received function ${actual.name}`;
  } else if (typeof actual === "object" && actual != null) {
    if (actual.constructor?.name) {
      msg += ` Received an instance of ${actual.constructor.name}`;
    }
  }
  return msg;
}
var invalidKeyInput = (actual, ...types) => message("Key must be ", actual, ...types);
var withAlg = (alg, actual, ...types) => message(`Key for the ${alg} algorithm must be `, actual, ...types);

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/util/errors.js
var JOSEError = class extends Error {
  static code = "ERR_JOSE_GENERIC";
  code = "ERR_JOSE_GENERIC";
  constructor(message2, options) {
    super(message2, options);
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
};
var JWTClaimValidationFailed = class extends JOSEError {
  static code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  code = "ERR_JWT_CLAIM_VALIDATION_FAILED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, { cause: { claim, reason, payload } });
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
var JWTExpired = class extends JOSEError {
  static code = "ERR_JWT_EXPIRED";
  code = "ERR_JWT_EXPIRED";
  claim;
  reason;
  payload;
  constructor(message2, payload, claim = "unspecified", reason = "unspecified") {
    super(message2, { cause: { claim, reason, payload } });
    this.claim = claim;
    this.reason = reason;
    this.payload = payload;
  }
};
var JOSEAlgNotAllowed = class extends JOSEError {
  static code = "ERR_JOSE_ALG_NOT_ALLOWED";
  code = "ERR_JOSE_ALG_NOT_ALLOWED";
};
var JOSENotSupported = class extends JOSEError {
  static code = "ERR_JOSE_NOT_SUPPORTED";
  code = "ERR_JOSE_NOT_SUPPORTED";
};
var JWSInvalid = class extends JOSEError {
  static code = "ERR_JWS_INVALID";
  code = "ERR_JWS_INVALID";
};
var JWTInvalid = class extends JOSEError {
  static code = "ERR_JWT_INVALID";
  code = "ERR_JWT_INVALID";
};
var JWSSignatureVerificationFailed = class extends JOSEError {
  static code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  code = "ERR_JWS_SIGNATURE_VERIFICATION_FAILED";
  constructor(message2 = "signature verification failed", options) {
    super(message2, options);
  }
};

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/is_key_like.js
var isCryptoKey = (key) => {
  if (key?.[Symbol.toStringTag] === "CryptoKey")
    return true;
  try {
    return key instanceof CryptoKey;
  } catch {
    return false;
  }
};
var isKeyObject = (key) => key?.[Symbol.toStringTag] === "KeyObject";
var isKeyLike = (key) => isCryptoKey(key) || isKeyObject(key);

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/helpers.js
function assertNotSet(value, name) {
  if (value) {
    throw new TypeError(`${name} can only be called once`);
  }
}
function decodeBase64url(value, label, ErrorClass) {
  try {
    return decode(value);
  } catch {
    throw new ErrorClass(`Failed to base64url decode the ${label}`);
  }
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/type_checks.js
var isObjectLike = (value) => typeof value === "object" && value !== null;
function isObject(input) {
  if (!isObjectLike(input) || Object.prototype.toString.call(input) !== "[object Object]") {
    return false;
  }
  if (Object.getPrototypeOf(input) === null) {
    return true;
  }
  let proto = input;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(input) === proto;
}
function isDisjoint(...headers) {
  const sources = headers.filter(Boolean);
  if (sources.length === 0 || sources.length === 1) {
    return true;
  }
  let acc;
  for (const header of sources) {
    const parameters = Object.keys(header);
    if (!acc || acc.size === 0) {
      acc = new Set(parameters);
      continue;
    }
    for (const parameter of parameters) {
      if (acc.has(parameter)) {
        return false;
      }
      acc.add(parameter);
    }
  }
  return true;
}
var isJWK = (key) => isObject(key) && typeof key.kty === "string";
var isPrivateJWK = (key) => key.kty !== "oct" && (key.kty === "AKP" && typeof key.priv === "string" || typeof key.d === "string");
var isPublicJWK = (key) => key.kty !== "oct" && key.d === void 0 && key.priv === void 0;
var isSecretJWK = (key) => key.kty === "oct" && typeof key.k === "string";

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/signing.js
function checkKeyLength(alg, key) {
  if (alg.startsWith("RS") || alg.startsWith("PS")) {
    const { modulusLength } = key.algorithm;
    if (typeof modulusLength !== "number" || modulusLength < 2048) {
      throw new TypeError(`${alg} requires key modulusLength to be 2048 bits or larger`);
    }
  }
}
function subtleAlgorithm(alg, algorithm) {
  const hash = `SHA-${alg.slice(-3)}`;
  switch (alg) {
    case "HS256":
    case "HS384":
    case "HS512":
      return { hash, name: "HMAC" };
    case "PS256":
    case "PS384":
    case "PS512":
      return { hash, name: "RSA-PSS", saltLength: parseInt(alg.slice(-3), 10) >> 3 };
    case "RS256":
    case "RS384":
    case "RS512":
      return { hash, name: "RSASSA-PKCS1-v1_5" };
    case "ES256":
    case "ES384":
    case "ES512":
      return { hash, name: "ECDSA", namedCurve: algorithm.namedCurve };
    case "Ed25519":
    case "EdDSA":
      return { name: "Ed25519" };
    case "ML-DSA-44":
    case "ML-DSA-65":
    case "ML-DSA-87":
      return { name: alg };
    default:
      throw new JOSENotSupported(`alg ${alg} is not supported either by JOSE or your javascript runtime`);
  }
}
async function getSigKey(alg, key, usage) {
  if (key instanceof Uint8Array) {
    if (!alg.startsWith("HS")) {
      throw new TypeError(invalidKeyInput(key, "CryptoKey", "KeyObject", "JSON Web Key"));
    }
    return crypto.subtle.importKey("raw", key, { hash: `SHA-${alg.slice(-3)}`, name: "HMAC" }, false, [usage]);
  }
  checkSigCryptoKey(key, alg, usage);
  return key;
}
async function sign(alg, key, data) {
  const cryptoKey = await getSigKey(alg, key, "sign");
  checkKeyLength(alg, cryptoKey);
  const signature = await crypto.subtle.sign(subtleAlgorithm(alg, cryptoKey.algorithm), cryptoKey, data);
  return new Uint8Array(signature);
}
async function verify(alg, key, signature, data) {
  const cryptoKey = await getSigKey(alg, key, "verify");
  checkKeyLength(alg, cryptoKey);
  const algorithm = subtleAlgorithm(alg, cryptoKey.algorithm);
  try {
    return await crypto.subtle.verify(algorithm, cryptoKey, signature, data);
  } catch {
    return false;
  }
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/jwk_to_key.js
var unsupportedAlg = 'Invalid or unsupported JWK "alg" (Algorithm) Parameter value';
function subtleMapping(jwk) {
  let algorithm;
  let keyUsages;
  switch (jwk.kty) {
    case "AKP": {
      switch (jwk.alg) {
        case "ML-DSA-44":
        case "ML-DSA-65":
        case "ML-DSA-87":
          algorithm = { name: jwk.alg };
          keyUsages = jwk.priv ? ["sign"] : ["verify"];
          break;
        default:
          throw new JOSENotSupported(unsupportedAlg);
      }
      break;
    }
    case "RSA": {
      switch (jwk.alg) {
        case "PS256":
        case "PS384":
        case "PS512":
          algorithm = { name: "RSA-PSS", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RS256":
        case "RS384":
        case "RS512":
          algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${jwk.alg.slice(-3)}` };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "RSA-OAEP":
        case "RSA-OAEP-256":
        case "RSA-OAEP-384":
        case "RSA-OAEP-512":
          algorithm = {
            name: "RSA-OAEP",
            hash: `SHA-${parseInt(jwk.alg.slice(-3), 10) || 1}`
          };
          keyUsages = jwk.d ? ["decrypt", "unwrapKey"] : ["encrypt", "wrapKey"];
          break;
        default:
          throw new JOSENotSupported(unsupportedAlg);
      }
      break;
    }
    case "EC": {
      switch (jwk.alg) {
        case "ES256":
        case "ES384":
        case "ES512":
          algorithm = {
            name: "ECDSA",
            namedCurve: { ES256: "P-256", ES384: "P-384", ES512: "P-521" }[jwk.alg]
          };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: "ECDH", namedCurve: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported(unsupportedAlg);
      }
      break;
    }
    case "OKP": {
      switch (jwk.alg) {
        case "Ed25519":
        case "EdDSA":
          algorithm = { name: "Ed25519" };
          keyUsages = jwk.d ? ["sign"] : ["verify"];
          break;
        case "ECDH-ES":
        case "ECDH-ES+A128KW":
        case "ECDH-ES+A192KW":
        case "ECDH-ES+A256KW":
          algorithm = { name: jwk.crv };
          keyUsages = jwk.d ? ["deriveBits"] : [];
          break;
        default:
          throw new JOSENotSupported(unsupportedAlg);
      }
      break;
    }
    default:
      throw new JOSENotSupported('Invalid or unsupported JWK "kty" (Key Type) Parameter value');
  }
  return { algorithm, keyUsages };
}
async function jwkToKey(jwk) {
  if (!jwk.alg) {
    throw new TypeError('"alg" argument is required when "jwk.alg" is not present');
  }
  const { algorithm, keyUsages } = subtleMapping(jwk);
  const keyData = { ...jwk };
  if (keyData.kty !== "AKP") {
    delete keyData.alg;
  }
  delete keyData.use;
  return crypto.subtle.importKey("jwk", keyData, algorithm, jwk.ext ?? (jwk.d || jwk.priv ? false : true), jwk.key_ops ?? keyUsages);
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/normalize_key.js
var unusableForAlg = "given KeyObject instance cannot be used for this algorithm";
var cache;
var handleJWK = async (key, jwk, alg, freeze = false) => {
  cache ||= /* @__PURE__ */ new WeakMap();
  let cached = cache.get(key);
  if (cached?.[alg]) {
    return cached[alg];
  }
  const cryptoKey = await jwkToKey({ ...jwk, alg });
  if (freeze)
    Object.freeze(key);
  if (!cached) {
    cache.set(key, { [alg]: cryptoKey });
  } else {
    cached[alg] = cryptoKey;
  }
  return cryptoKey;
};
var handleKeyObject = (keyObject, alg) => {
  cache ||= /* @__PURE__ */ new WeakMap();
  let cached = cache.get(keyObject);
  if (cached?.[alg]) {
    return cached[alg];
  }
  const isPublic = keyObject.type === "public";
  const extractable = isPublic ? true : false;
  let cryptoKey;
  if (keyObject.asymmetricKeyType === "x25519") {
    switch (alg) {
      case "ECDH-ES":
      case "ECDH-ES+A128KW":
      case "ECDH-ES+A192KW":
      case "ECDH-ES+A256KW":
        break;
      default:
        throw new TypeError(unusableForAlg);
    }
    cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, isPublic ? [] : ["deriveBits"]);
  }
  if (keyObject.asymmetricKeyType === "ed25519") {
    if (alg !== "EdDSA" && alg !== "Ed25519") {
      throw new TypeError(unusableForAlg);
    }
    cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, [
      isPublic ? "verify" : "sign"
    ]);
  }
  switch (keyObject.asymmetricKeyType) {
    case "ml-dsa-44":
    case "ml-dsa-65":
    case "ml-dsa-87": {
      if (alg !== keyObject.asymmetricKeyType.toUpperCase()) {
        throw new TypeError(unusableForAlg);
      }
      cryptoKey = keyObject.toCryptoKey(keyObject.asymmetricKeyType, extractable, [
        isPublic ? "verify" : "sign"
      ]);
    }
  }
  if (keyObject.asymmetricKeyType === "rsa") {
    let hash;
    switch (alg) {
      case "RSA-OAEP":
        hash = "SHA-1";
        break;
      case "RS256":
      case "PS256":
      case "RSA-OAEP-256":
        hash = "SHA-256";
        break;
      case "RS384":
      case "PS384":
      case "RSA-OAEP-384":
        hash = "SHA-384";
        break;
      case "RS512":
      case "PS512":
      case "RSA-OAEP-512":
        hash = "SHA-512";
        break;
      default:
        throw new TypeError(unusableForAlg);
    }
    if (alg.startsWith("RSA-OAEP")) {
      return keyObject.toCryptoKey({
        name: "RSA-OAEP",
        hash
      }, extractable, isPublic ? ["encrypt"] : ["decrypt"]);
    }
    cryptoKey = keyObject.toCryptoKey({
      name: alg.startsWith("PS") ? "RSA-PSS" : "RSASSA-PKCS1-v1_5",
      hash
    }, extractable, [isPublic ? "verify" : "sign"]);
  }
  if (keyObject.asymmetricKeyType === "ec") {
    const nist = /* @__PURE__ */ new Map([
      ["prime256v1", "P-256"],
      ["secp384r1", "P-384"],
      ["secp521r1", "P-521"]
    ]);
    const namedCurve = nist.get(keyObject.asymmetricKeyDetails?.namedCurve);
    if (!namedCurve) {
      throw new TypeError(unusableForAlg);
    }
    const expectedCurve = { ES256: "P-256", ES384: "P-384", ES512: "P-521" };
    if (expectedCurve[alg] && namedCurve === expectedCurve[alg]) {
      cryptoKey = keyObject.toCryptoKey({
        name: "ECDSA",
        namedCurve
      }, extractable, [isPublic ? "verify" : "sign"]);
    }
    if (alg.startsWith("ECDH-ES")) {
      cryptoKey = keyObject.toCryptoKey({
        name: "ECDH",
        namedCurve
      }, extractable, isPublic ? [] : ["deriveBits"]);
    }
  }
  if (!cryptoKey) {
    throw new TypeError(unusableForAlg);
  }
  if (!cached) {
    cache.set(keyObject, { [alg]: cryptoKey });
  } else {
    cached[alg] = cryptoKey;
  }
  return cryptoKey;
};
async function normalizeKey(key, alg) {
  if (key instanceof Uint8Array) {
    return key;
  }
  if (isCryptoKey(key)) {
    return key;
  }
  if (isKeyObject(key)) {
    if (key.type === "secret") {
      return key.export();
    }
    if ("toCryptoKey" in key && typeof key.toCryptoKey === "function") {
      try {
        return handleKeyObject(key, alg);
      } catch (err) {
        if (err instanceof TypeError) {
          throw err;
        }
      }
    }
    let jwk = key.export({ format: "jwk" });
    return handleJWK(key, jwk, alg);
  }
  if (isJWK(key)) {
    if (key.k) {
      return decode(key.k);
    }
    return handleJWK(key, key, alg, true);
  }
  throw new Error("unreachable");
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/asn1.js
var bytesEqual = (a, b) => {
  if (a.byteLength !== b.length)
    return false;
  for (let i = 0; i < a.byteLength; i++) {
    if (a[i] !== b[i])
      return false;
  }
  return true;
};
var createASN1State = (data) => ({ data, pos: 0 });
var parseLength = (state) => {
  const first = state.data[state.pos++];
  if (first & 128) {
    const lengthOfLen = first & 127;
    let length = 0;
    for (let i = 0; i < lengthOfLen; i++) {
      length = length << 8 | state.data[state.pos++];
    }
    return length;
  }
  return first;
};
var expectTag = (state, expectedTag, errorMessage) => {
  if (state.data[state.pos++] !== expectedTag) {
    throw new Error(errorMessage);
  }
};
var getSubarray = (state, length) => {
  const result = state.data.subarray(state.pos, state.pos + length);
  state.pos += length;
  return result;
};
var parseAlgorithmOID = (state) => {
  expectTag(state, 6, "Expected algorithm OID");
  const oidLen = parseLength(state);
  return getSubarray(state, oidLen);
};
function parsePKCS8Header(state) {
  expectTag(state, 48, "Invalid PKCS#8 structure");
  parseLength(state);
  expectTag(state, 2, "Expected version field");
  const verLen = parseLength(state);
  state.pos += verLen;
  expectTag(state, 48, "Expected algorithm identifier");
  const algIdLen = parseLength(state);
  const algIdStart = state.pos;
  return { algIdStart, algIdLength: algIdLen };
}
function parseSPKIHeader(state) {
  expectTag(state, 48, "Invalid SPKI structure");
  parseLength(state);
  expectTag(state, 48, "Expected algorithm identifier");
  const algIdLen = parseLength(state);
  const algIdStart = state.pos;
  return { algIdStart, algIdLength: algIdLen };
}
var parseECAlgorithmIdentifier = (state) => {
  const algOid = parseAlgorithmOID(state);
  if (bytesEqual(algOid, [43, 101, 110])) {
    return "X25519";
  }
  if (!bytesEqual(algOid, [42, 134, 72, 206, 61, 2, 1])) {
    throw new Error("Unsupported key algorithm");
  }
  expectTag(state, 6, "Expected curve OID");
  const curveOidLen = parseLength(state);
  const curveOid = getSubarray(state, curveOidLen);
  for (const { name, oid } of [
    { name: "P-256", oid: [42, 134, 72, 206, 61, 3, 1, 7] },
    { name: "P-384", oid: [43, 129, 4, 0, 34] },
    { name: "P-521", oid: [43, 129, 4, 0, 35] }
  ]) {
    if (bytesEqual(curveOid, oid)) {
      return name;
    }
  }
  throw new Error("Unsupported named curve");
};
var genericImport = async (keyFormat, keyData, alg, options) => {
  let algorithm;
  let keyUsages;
  const isPublic = keyFormat === "spki";
  const getSigUsages = () => isPublic ? ["verify"] : ["sign"];
  const getEncUsages = () => isPublic ? ["encrypt", "wrapKey"] : ["decrypt", "unwrapKey"];
  switch (alg) {
    case "PS256":
    case "PS384":
    case "PS512":
      algorithm = { name: "RSA-PSS", hash: `SHA-${alg.slice(-3)}` };
      keyUsages = getSigUsages();
      break;
    case "RS256":
    case "RS384":
    case "RS512":
      algorithm = { name: "RSASSA-PKCS1-v1_5", hash: `SHA-${alg.slice(-3)}` };
      keyUsages = getSigUsages();
      break;
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "RSA-OAEP-384":
    case "RSA-OAEP-512":
      algorithm = {
        name: "RSA-OAEP",
        hash: `SHA-${parseInt(alg.slice(-3), 10) || 1}`
      };
      keyUsages = getEncUsages();
      break;
    case "ES256":
    case "ES384":
    case "ES512": {
      const curveMap = { ES256: "P-256", ES384: "P-384", ES512: "P-521" };
      algorithm = { name: "ECDSA", namedCurve: curveMap[alg] };
      keyUsages = getSigUsages();
      break;
    }
    case "ECDH-ES":
    case "ECDH-ES+A128KW":
    case "ECDH-ES+A192KW":
    case "ECDH-ES+A256KW": {
      try {
        const namedCurve = options.getNamedCurve(keyData);
        algorithm = namedCurve === "X25519" ? { name: "X25519" } : { name: "ECDH", namedCurve };
      } catch (cause) {
        throw new JOSENotSupported("Invalid or unsupported key format");
      }
      keyUsages = isPublic ? [] : ["deriveBits"];
      break;
    }
    case "Ed25519":
    case "EdDSA":
      algorithm = { name: "Ed25519" };
      keyUsages = getSigUsages();
      break;
    case "ML-DSA-44":
    case "ML-DSA-65":
    case "ML-DSA-87":
      algorithm = { name: alg };
      keyUsages = getSigUsages();
      break;
    default:
      throw new JOSENotSupported('Invalid or unsupported "alg" (Algorithm) value');
  }
  return crypto.subtle.importKey(keyFormat, keyData, algorithm, options?.extractable ?? (isPublic ? true : false), keyUsages);
};
var processPEMData = (pem, pattern) => {
  return decodeBase642(pem.replace(pattern, ""));
};
var fromPKCS8 = (pem, alg, options) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PRIVATE KEY-----|\s)/g);
  let opts = options;
  if (alg?.startsWith?.("ECDH-ES")) {
    opts ||= {};
    opts.getNamedCurve = (keyData2) => {
      const state = createASN1State(keyData2);
      parsePKCS8Header(state);
      return parseECAlgorithmIdentifier(state);
    };
  }
  return genericImport("pkcs8", keyData, alg, opts);
};
var fromSPKI = (pem, alg, options) => {
  const keyData = processPEMData(pem, /(?:-----(?:BEGIN|END) PUBLIC KEY-----|\s)/g);
  let opts = options;
  if (alg?.startsWith?.("ECDH-ES")) {
    opts ||= {};
    opts.getNamedCurve = (keyData2) => {
      const state = createASN1State(keyData2);
      parseSPKIHeader(state);
      return parseECAlgorithmIdentifier(state);
    };
  }
  return genericImport("spki", keyData, alg, opts);
};

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/key/import.js
async function importSPKI(spki, alg, options) {
  if (typeof spki !== "string" || spki.indexOf("-----BEGIN PUBLIC KEY-----") !== 0) {
    throw new TypeError('"spki" must be SPKI formatted string');
  }
  return fromSPKI(spki, alg, options);
}
async function importPKCS8(pkcs8, alg, options) {
  if (typeof pkcs8 !== "string" || pkcs8.indexOf("-----BEGIN PRIVATE KEY-----") !== 0) {
    throw new TypeError('"pkcs8" must be PKCS#8 formatted string');
  }
  return fromPKCS8(pkcs8, alg, options);
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/validate_crit.js
function validateCrit(Err, recognizedDefault, recognizedOption, protectedHeader, joseHeader) {
  if (joseHeader.crit !== void 0 && protectedHeader?.crit === void 0) {
    throw new Err('"crit" (Critical) Header Parameter MUST be integrity protected');
  }
  if (!protectedHeader || protectedHeader.crit === void 0) {
    return /* @__PURE__ */ new Set();
  }
  if (!Array.isArray(protectedHeader.crit) || protectedHeader.crit.length === 0 || protectedHeader.crit.some((input) => typeof input !== "string" || input.length === 0)) {
    throw new Err('"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present');
  }
  let recognized;
  if (recognizedOption !== void 0) {
    recognized = new Map([...Object.entries(recognizedOption), ...recognizedDefault.entries()]);
  } else {
    recognized = recognizedDefault;
  }
  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JOSENotSupported(`Extension Header Parameter "${parameter}" is not recognized`);
    }
    if (joseHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }
    if (recognized.get(parameter) && protectedHeader[parameter] === void 0) {
      throw new Err(`Extension Header Parameter "${parameter}" MUST be integrity protected`);
    }
  }
  return new Set(protectedHeader.crit);
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/validate_algorithms.js
function validateAlgorithms(option, algorithms) {
  if (algorithms !== void 0 && (!Array.isArray(algorithms) || algorithms.some((s) => typeof s !== "string"))) {
    throw new TypeError(`"${option}" option must be an array of strings`);
  }
  if (!algorithms) {
    return void 0;
  }
  return new Set(algorithms);
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/check_key_type.js
var tag = (key) => key?.[Symbol.toStringTag];
var jwkMatchesOp = (alg, key, usage) => {
  if (key.use !== void 0) {
    let expected;
    switch (usage) {
      case "sign":
      case "verify":
        expected = "sig";
        break;
      case "encrypt":
      case "decrypt":
        expected = "enc";
        break;
    }
    if (key.use !== expected) {
      throw new TypeError(`Invalid key for this operation, its "use" must be "${expected}" when present`);
    }
  }
  if (key.alg !== void 0 && key.alg !== alg) {
    throw new TypeError(`Invalid key for this operation, its "alg" must be "${alg}" when present`);
  }
  if (Array.isArray(key.key_ops)) {
    let expectedKeyOp;
    switch (true) {
      case (usage === "sign" || usage === "verify"):
      case alg === "dir":
      case alg.includes("CBC-HS"):
        expectedKeyOp = usage;
        break;
      case alg.startsWith("PBES2"):
        expectedKeyOp = "deriveBits";
        break;
      case /^A\d{3}(?:GCM)?(?:KW)?$/.test(alg):
        if (!alg.includes("GCM") && alg.endsWith("KW")) {
          expectedKeyOp = usage === "encrypt" ? "wrapKey" : "unwrapKey";
        } else {
          expectedKeyOp = usage;
        }
        break;
      case (usage === "encrypt" && alg.startsWith("RSA")):
        expectedKeyOp = "wrapKey";
        break;
      case usage === "decrypt":
        expectedKeyOp = alg.startsWith("RSA") ? "unwrapKey" : "deriveBits";
        break;
    }
    if (expectedKeyOp && key.key_ops?.includes?.(expectedKeyOp) === false) {
      throw new TypeError(`Invalid key for this operation, its "key_ops" must include "${expectedKeyOp}" when present`);
    }
  }
  return true;
};
var symmetricTypeCheck = (alg, key, usage) => {
  if (key instanceof Uint8Array)
    return;
  if (isJWK(key)) {
    if (isSecretJWK(key) && jwkMatchesOp(alg, key, usage))
      return;
    throw new TypeError(`JSON Web Key for symmetric algorithms must have JWK "kty" (Key Type) equal to "oct" and the JWK "k" (Key Value) present`);
  }
  if (!isKeyLike(key)) {
    throw new TypeError(withAlg(alg, key, "CryptoKey", "KeyObject", "JSON Web Key", "Uint8Array"));
  }
  if (key.type !== "secret") {
    throw new TypeError(`${tag(key)} instances for symmetric algorithms must be of type "secret"`);
  }
};
var asymmetricTypeCheck = (alg, key, usage) => {
  if (isJWK(key)) {
    switch (usage) {
      case "decrypt":
      case "sign":
        if (isPrivateJWK(key) && jwkMatchesOp(alg, key, usage))
          return;
        throw new TypeError(`JSON Web Key for this operation must be a private JWK`);
      case "encrypt":
      case "verify":
        if (isPublicJWK(key) && jwkMatchesOp(alg, key, usage))
          return;
        throw new TypeError(`JSON Web Key for this operation must be a public JWK`);
    }
  }
  if (!isKeyLike(key)) {
    throw new TypeError(withAlg(alg, key, "CryptoKey", "KeyObject", "JSON Web Key"));
  }
  if (key.type === "secret") {
    throw new TypeError(`${tag(key)} instances for asymmetric algorithms must not be of type "secret"`);
  }
  if (key.type === "public") {
    switch (usage) {
      case "sign":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm signing must be of type "private"`);
      case "decrypt":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm decryption must be of type "private"`);
    }
  }
  if (key.type === "private") {
    switch (usage) {
      case "verify":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm verifying must be of type "public"`);
      case "encrypt":
        throw new TypeError(`${tag(key)} instances for asymmetric algorithm encryption must be of type "public"`);
    }
  }
};
function checkKeyType(alg, key, usage) {
  switch (alg.substring(0, 2)) {
    case "A1":
    case "A2":
    case "di":
    case "HS":
    case "PB":
      symmetricTypeCheck(alg, key, usage);
      break;
    default:
      asymmetricTypeCheck(alg, key, usage);
  }
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/jws/flattened/verify.js
async function flattenedVerify(jws, key, options) {
  if (!isObject(jws)) {
    throw new JWSInvalid("Flattened JWS must be an object");
  }
  if (jws.protected === void 0 && jws.header === void 0) {
    throw new JWSInvalid('Flattened JWS must have either of the "protected" or "header" members');
  }
  if (jws.protected !== void 0 && typeof jws.protected !== "string") {
    throw new JWSInvalid("JWS Protected Header incorrect type");
  }
  if (jws.payload === void 0) {
    throw new JWSInvalid("JWS Payload missing");
  }
  if (typeof jws.signature !== "string") {
    throw new JWSInvalid("JWS Signature missing or incorrect type");
  }
  if (jws.header !== void 0 && !isObject(jws.header)) {
    throw new JWSInvalid("JWS Unprotected Header incorrect type");
  }
  let parsedProt = {};
  if (jws.protected) {
    try {
      const protectedHeader = decode(jws.protected);
      parsedProt = JSON.parse(decoder.decode(protectedHeader));
    } catch {
      throw new JWSInvalid("JWS Protected Header is invalid");
    }
  }
  if (!isDisjoint(parsedProt, jws.header)) {
    throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
  }
  const joseHeader = {
    ...parsedProt,
    ...jws.header
  };
  const extensions = validateCrit(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, parsedProt, joseHeader);
  let b642 = true;
  if (extensions.has("b64")) {
    b642 = parsedProt.b64;
    if (typeof b642 !== "boolean") {
      throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
    }
  }
  const { alg } = joseHeader;
  if (typeof alg !== "string" || !alg) {
    throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
  }
  const algorithms = options && validateAlgorithms("algorithms", options.algorithms);
  if (algorithms && !algorithms.has(alg)) {
    throw new JOSEAlgNotAllowed('"alg" (Algorithm) Header Parameter value not allowed');
  }
  if (b642) {
    if (typeof jws.payload !== "string") {
      throw new JWSInvalid("JWS Payload must be a string");
    }
  } else if (typeof jws.payload !== "string" && !(jws.payload instanceof Uint8Array)) {
    throw new JWSInvalid("JWS Payload must be a string or an Uint8Array instance");
  }
  let resolvedKey = false;
  if (typeof key === "function") {
    key = await key(parsedProt, jws);
    resolvedKey = true;
  }
  checkKeyType(alg, key, "verify");
  const data = concat(jws.protected !== void 0 ? encode(jws.protected) : new Uint8Array(), encode("."), typeof jws.payload === "string" ? b642 ? encode(jws.payload) : encoder.encode(jws.payload) : jws.payload);
  const signature = decodeBase64url(jws.signature, "signature", JWSInvalid);
  const k = await normalizeKey(key, alg);
  const verified = await verify(alg, k, signature, data);
  if (!verified) {
    throw new JWSSignatureVerificationFailed();
  }
  let payload;
  if (b642) {
    payload = decodeBase64url(jws.payload, "payload", JWSInvalid);
  } else if (typeof jws.payload === "string") {
    payload = encoder.encode(jws.payload);
  } else {
    payload = jws.payload;
  }
  const result = { payload };
  if (jws.protected !== void 0) {
    result.protectedHeader = parsedProt;
  }
  if (jws.header !== void 0) {
    result.unprotectedHeader = jws.header;
  }
  if (resolvedKey) {
    return { ...result, key: k };
  }
  return result;
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/jws/compact/verify.js
async function compactVerify(jws, key, options) {
  if (jws instanceof Uint8Array) {
    jws = decoder.decode(jws);
  }
  if (typeof jws !== "string") {
    throw new JWSInvalid("Compact JWS must be a string or Uint8Array");
  }
  const { 0: protectedHeader, 1: payload, 2: signature, length } = jws.split(".");
  if (length !== 3) {
    throw new JWSInvalid("Invalid Compact JWS");
  }
  const verified = await flattenedVerify({ payload, protected: protectedHeader, signature }, key, options);
  const result = { payload: verified.payload, protectedHeader: verified.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: verified.key };
  }
  return result;
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/lib/jwt_claims_set.js
var epoch = (date) => Math.floor(date.getTime() / 1e3);
var minute = 60;
var hour = minute * 60;
var day = hour * 24;
var week = day * 7;
var year = day * 365.25;
var REGEX = /^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$/i;
function secs(str3) {
  const matched = REGEX.exec(str3);
  if (!matched || matched[4] && matched[1]) {
    throw new TypeError("Invalid time period format");
  }
  const value = parseFloat(matched[2]);
  const unit = matched[3].toLowerCase();
  let numericDate;
  switch (unit) {
    case "sec":
    case "secs":
    case "second":
    case "seconds":
    case "s":
      numericDate = Math.round(value);
      break;
    case "minute":
    case "minutes":
    case "min":
    case "mins":
    case "m":
      numericDate = Math.round(value * minute);
      break;
    case "hour":
    case "hours":
    case "hr":
    case "hrs":
    case "h":
      numericDate = Math.round(value * hour);
      break;
    case "day":
    case "days":
    case "d":
      numericDate = Math.round(value * day);
      break;
    case "week":
    case "weeks":
    case "w":
      numericDate = Math.round(value * week);
      break;
    default:
      numericDate = Math.round(value * year);
      break;
  }
  if (matched[1] === "-" || matched[4] === "ago") {
    return -numericDate;
  }
  return numericDate;
}
function validateInput(label, input) {
  if (!Number.isFinite(input)) {
    throw new TypeError(`Invalid ${label} input`);
  }
  return input;
}
var normalizeTyp = (value) => {
  if (value.includes("/")) {
    return value.toLowerCase();
  }
  return `application/${value.toLowerCase()}`;
};
var checkAudiencePresence = (audPayload, audOption) => {
  if (typeof audPayload === "string") {
    return audOption.includes(audPayload);
  }
  if (Array.isArray(audPayload)) {
    return audOption.some(Set.prototype.has.bind(new Set(audPayload)));
  }
  return false;
};
function validateClaimsSet(protectedHeader, encodedPayload, options = {}) {
  let payload;
  try {
    payload = JSON.parse(decoder.decode(encodedPayload));
  } catch {
  }
  if (!isObject(payload)) {
    throw new JWTInvalid("JWT Claims Set must be a top-level JSON object");
  }
  const { typ } = options;
  if (typ && (typeof protectedHeader.typ !== "string" || normalizeTyp(protectedHeader.typ) !== normalizeTyp(typ))) {
    throw new JWTClaimValidationFailed('unexpected "typ" JWT header value', payload, "typ", "check_failed");
  }
  const { requiredClaims = [], issuer, subject, audience, maxTokenAge } = options;
  const presenceCheck = [...requiredClaims];
  if (maxTokenAge !== void 0)
    presenceCheck.push("iat");
  if (audience !== void 0)
    presenceCheck.push("aud");
  if (subject !== void 0)
    presenceCheck.push("sub");
  if (issuer !== void 0)
    presenceCheck.push("iss");
  for (const claim of new Set(presenceCheck.reverse())) {
    if (!(claim in payload)) {
      throw new JWTClaimValidationFailed(`missing required "${claim}" claim`, payload, claim, "missing");
    }
  }
  if (issuer && !(Array.isArray(issuer) ? issuer : [issuer]).includes(payload.iss)) {
    throw new JWTClaimValidationFailed('unexpected "iss" claim value', payload, "iss", "check_failed");
  }
  if (subject && payload.sub !== subject) {
    throw new JWTClaimValidationFailed('unexpected "sub" claim value', payload, "sub", "check_failed");
  }
  if (audience && !checkAudiencePresence(payload.aud, typeof audience === "string" ? [audience] : audience)) {
    throw new JWTClaimValidationFailed('unexpected "aud" claim value', payload, "aud", "check_failed");
  }
  let tolerance;
  switch (typeof options.clockTolerance) {
    case "string":
      tolerance = secs(options.clockTolerance);
      break;
    case "number":
      tolerance = options.clockTolerance;
      break;
    case "undefined":
      tolerance = 0;
      break;
    default:
      throw new TypeError("Invalid clockTolerance option type");
  }
  const { currentDate } = options;
  const now = epoch(currentDate || /* @__PURE__ */ new Date());
  if ((payload.iat !== void 0 || maxTokenAge) && typeof payload.iat !== "number") {
    throw new JWTClaimValidationFailed('"iat" claim must be a number', payload, "iat", "invalid");
  }
  if (payload.nbf !== void 0) {
    if (typeof payload.nbf !== "number") {
      throw new JWTClaimValidationFailed('"nbf" claim must be a number', payload, "nbf", "invalid");
    }
    if (payload.nbf > now + tolerance) {
      throw new JWTClaimValidationFailed('"nbf" claim timestamp check failed', payload, "nbf", "check_failed");
    }
  }
  if (payload.exp !== void 0) {
    if (typeof payload.exp !== "number") {
      throw new JWTClaimValidationFailed('"exp" claim must be a number', payload, "exp", "invalid");
    }
    if (payload.exp <= now - tolerance) {
      throw new JWTExpired('"exp" claim timestamp check failed', payload, "exp", "check_failed");
    }
  }
  if (maxTokenAge) {
    const age = now - payload.iat;
    const max = typeof maxTokenAge === "number" ? maxTokenAge : secs(maxTokenAge);
    if (age - tolerance > max) {
      throw new JWTExpired('"iat" claim timestamp check failed (too far in the past)', payload, "iat", "check_failed");
    }
    if (age < 0 - tolerance) {
      throw new JWTClaimValidationFailed('"iat" claim timestamp check failed (it should be in the past)', payload, "iat", "check_failed");
    }
  }
  return payload;
}
var JWTClaimsBuilder = class {
  #payload;
  constructor(payload) {
    if (!isObject(payload)) {
      throw new TypeError("JWT Claims Set MUST be an object");
    }
    this.#payload = structuredClone(payload);
  }
  data() {
    return encoder.encode(JSON.stringify(this.#payload));
  }
  get iss() {
    return this.#payload.iss;
  }
  set iss(value) {
    this.#payload.iss = value;
  }
  get sub() {
    return this.#payload.sub;
  }
  set sub(value) {
    this.#payload.sub = value;
  }
  get aud() {
    return this.#payload.aud;
  }
  set aud(value) {
    this.#payload.aud = value;
  }
  set jti(value) {
    this.#payload.jti = value;
  }
  set nbf(value) {
    if (typeof value === "number") {
      this.#payload.nbf = validateInput("setNotBefore", value);
    } else if (value instanceof Date) {
      this.#payload.nbf = validateInput("setNotBefore", epoch(value));
    } else {
      this.#payload.nbf = epoch(/* @__PURE__ */ new Date()) + secs(value);
    }
  }
  set exp(value) {
    if (typeof value === "number") {
      this.#payload.exp = validateInput("setExpirationTime", value);
    } else if (value instanceof Date) {
      this.#payload.exp = validateInput("setExpirationTime", epoch(value));
    } else {
      this.#payload.exp = epoch(/* @__PURE__ */ new Date()) + secs(value);
    }
  }
  set iat(value) {
    if (value === void 0) {
      this.#payload.iat = epoch(/* @__PURE__ */ new Date());
    } else if (value instanceof Date) {
      this.#payload.iat = validateInput("setIssuedAt", epoch(value));
    } else if (typeof value === "string") {
      this.#payload.iat = validateInput("setIssuedAt", epoch(/* @__PURE__ */ new Date()) + secs(value));
    } else {
      this.#payload.iat = validateInput("setIssuedAt", value);
    }
  }
};

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/jwt/verify.js
async function jwtVerify(jwt, key, options) {
  const verified = await compactVerify(jwt, key, options);
  if (verified.protectedHeader.crit?.includes("b64") && verified.protectedHeader.b64 === false) {
    throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
  }
  const payload = validateClaimsSet(verified.protectedHeader, verified.payload, options);
  const result = { payload, protectedHeader: verified.protectedHeader };
  if (typeof key === "function") {
    return { ...result, key: verified.key };
  }
  return result;
}

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/jws/flattened/sign.js
var FlattenedSign = class {
  #payload;
  #protectedHeader;
  #unprotectedHeader;
  constructor(payload) {
    if (!(payload instanceof Uint8Array)) {
      throw new TypeError("payload must be an instance of Uint8Array");
    }
    this.#payload = payload;
  }
  setProtectedHeader(protectedHeader) {
    assertNotSet(this.#protectedHeader, "setProtectedHeader");
    this.#protectedHeader = protectedHeader;
    return this;
  }
  setUnprotectedHeader(unprotectedHeader) {
    assertNotSet(this.#unprotectedHeader, "setUnprotectedHeader");
    this.#unprotectedHeader = unprotectedHeader;
    return this;
  }
  async sign(key, options) {
    if (!this.#protectedHeader && !this.#unprotectedHeader) {
      throw new JWSInvalid("either setProtectedHeader or setUnprotectedHeader must be called before #sign()");
    }
    if (!isDisjoint(this.#protectedHeader, this.#unprotectedHeader)) {
      throw new JWSInvalid("JWS Protected and JWS Unprotected Header Parameter names must be disjoint");
    }
    const joseHeader = {
      ...this.#protectedHeader,
      ...this.#unprotectedHeader
    };
    const extensions = validateCrit(JWSInvalid, /* @__PURE__ */ new Map([["b64", true]]), options?.crit, this.#protectedHeader, joseHeader);
    let b642 = true;
    if (extensions.has("b64")) {
      b642 = this.#protectedHeader.b64;
      if (typeof b642 !== "boolean") {
        throw new JWSInvalid('The "b64" (base64url-encode payload) Header Parameter must be a boolean');
      }
    }
    const { alg } = joseHeader;
    if (typeof alg !== "string" || !alg) {
      throw new JWSInvalid('JWS "alg" (Algorithm) Header Parameter missing or invalid');
    }
    checkKeyType(alg, key, "sign");
    let payloadS;
    let payloadB;
    if (b642) {
      payloadS = encode2(this.#payload);
      payloadB = encode(payloadS);
    } else {
      payloadB = this.#payload;
      payloadS = "";
    }
    let protectedHeaderString;
    let protectedHeaderBytes;
    if (this.#protectedHeader) {
      protectedHeaderString = encode2(JSON.stringify(this.#protectedHeader));
      protectedHeaderBytes = encode(protectedHeaderString);
    } else {
      protectedHeaderString = "";
      protectedHeaderBytes = new Uint8Array();
    }
    const data = concat(protectedHeaderBytes, encode("."), payloadB);
    const k = await normalizeKey(key, alg);
    const signature = await sign(alg, k, data);
    const jws = {
      signature: encode2(signature),
      payload: payloadS
    };
    if (this.#unprotectedHeader) {
      jws.header = this.#unprotectedHeader;
    }
    if (this.#protectedHeader) {
      jws.protected = protectedHeaderString;
    }
    return jws;
  }
};

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/jws/compact/sign.js
var CompactSign = class {
  #flattened;
  constructor(payload) {
    this.#flattened = new FlattenedSign(payload);
  }
  setProtectedHeader(protectedHeader) {
    this.#flattened.setProtectedHeader(protectedHeader);
    return this;
  }
  async sign(key, options) {
    const jws = await this.#flattened.sign(key, options);
    if (jws.payload === void 0) {
      throw new TypeError("use the flattened module for creating JWS with b64: false");
    }
    return `${jws.protected}.${jws.payload}.${jws.signature}`;
  }
};

// ../../node_modules/.pnpm/jose@6.2.2/node_modules/jose/dist/webapi/jwt/sign.js
var SignJWT = class {
  #protectedHeader;
  #jwt;
  constructor(payload = {}) {
    this.#jwt = new JWTClaimsBuilder(payload);
  }
  setIssuer(issuer) {
    this.#jwt.iss = issuer;
    return this;
  }
  setSubject(subject) {
    this.#jwt.sub = subject;
    return this;
  }
  setAudience(audience) {
    this.#jwt.aud = audience;
    return this;
  }
  setJti(jwtId) {
    this.#jwt.jti = jwtId;
    return this;
  }
  setNotBefore(input) {
    this.#jwt.nbf = input;
    return this;
  }
  setExpirationTime(input) {
    this.#jwt.exp = input;
    return this;
  }
  setIssuedAt(input) {
    this.#jwt.iat = input;
    return this;
  }
  setProtectedHeader(protectedHeader) {
    this.#protectedHeader = protectedHeader;
    return this;
  }
  async sign(key, options) {
    const sig = new CompactSign(this.#jwt.data());
    sig.setProtectedHeader(this.#protectedHeader);
    if (Array.isArray(this.#protectedHeader?.crit) && this.#protectedHeader.crit.includes("b64") && this.#protectedHeader.b64 === false) {
      throw new JWTInvalid("JWTs MUST NOT use unencoded payload");
    }
    return sig.sign(key, options);
  }
};

// src/box-token.ts
function makeBoxTokenSigner(keysDir) {
  const read = (name) => readFileSync4(`${keysDir}/${name}`, "utf-8").trim();
  return async () => {
    const vmId = read("vm_id");
    const key = await importPKCS8(read("vm_private_key.pem"), "EdDSA");
    return new SignJWT({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
  };
}

// src/firewall-control.ts
import { execSync } from "child_process";
var ACTIONS = /* @__PURE__ */ new Set(["start", "stop", "restart"]);
var IS_ACTIVE_TIMEOUT_MS = 5e3;
function defaultExec(cmd, timeoutMs) {
  return execSync(cmd, { encoding: "utf-8", timeout: timeoutMs, stdio: ["ignore", "pipe", "pipe"] });
}
var FirewallControl = class {
  constructor(opts) {
    this.opts = opts;
    this.service = opts.service ?? "controlclaw-mitmproxy";
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.exec = opts.execImpl ?? defaultExec;
    this.actionTimeoutMs = opts.actionTimeoutMs ?? 3e4;
    this.log = opts.log ?? ((line) => console.log(line));
    this.handlers = opts.handlers ?? {};
  }
  inFlight = false;
  pendingResults = [];
  runs = /* @__PURE__ */ new Set();
  backoffMs = 0;
  nextAttemptAt = 0;
  down = false;
  startedAt = Date.now();
  service;
  fetchImpl;
  exec;
  actionTimeoutMs;
  log;
  handlers;
  /** `systemctl is-active` exits non-zero when the unit is not active; the state is still on stdout. */
  proxyStatus() {
    let out;
    try {
      out = this.exec(`systemctl is-active ${this.service}`, IS_ACTIVE_TIMEOUT_MS);
    } catch (err) {
      const e = err;
      out = e.stdout ? String(e.stdout) : "";
    }
    const s = out.trim();
    if (s === "active" || s === "activating" || s === "reloading") return "active";
    if (s === "failed") return "failed";
    return "inactive";
  }
  /** One heartbeat; a returned command runs in the background and reports on a beat of its own. */
  async tick() {
    if (this.inFlight) return;
    if (Date.now() < this.nextAttemptAt) return;
    this.inFlight = true;
    try {
      const command = await this.beat();
      if (command) this.launch(command);
    } finally {
      this.inFlight = false;
    }
  }
  /** Test hook: wait for background commands and their reporting beats. */
  async drain() {
    while (this.runs.size > 0) await Promise.all([...this.runs]);
  }
  launch(command) {
    const run = this.execute(command).then(async (result) => {
      this.pendingResults.push(result);
      await this.tick();
    }).finally(() => this.runs.delete(run));
    this.runs.add(run);
  }
  async execute(command) {
    if (ACTIONS.has(command.action)) return this.runService(command.id, command.action);
    const handler = this.handlers[command.action];
    if (!handler) {
      this.log(`[firewall] unknown command ${command.action} (${command.id})`);
      return { command_id: command.id, ok: false, status: "failed", message: `unknown command ${command.action}` };
    }
    this.log(`[firewall] ${command.action} (command ${command.id})`);
    try {
      const outcome = await handler(command.payload);
      return { command_id: command.id, ...outcome, message: outcome.message ?? "" };
    } catch (err) {
      const message2 = (err.message ?? "command failed").slice(0, 500);
      this.log(`[firewall] ${command.action} failed: ${message2}`);
      return { command_id: command.id, ok: false, status: "failed", message: message2 };
    }
  }
  async beat() {
    for (const r of this.opts.extraResults?.() ?? []) this.pendingResults.push(r);
    const results = this.pendingResults;
    const body = {
      proxy: this.proxyStatus(),
      agent_version: this.opts.agentVersion,
      uptime_s: Math.round((Date.now() - this.startedAt) / 1e3),
      ...results.length ? { results } : {}
    };
    let res;
    try {
      res = await this.fetchImpl(this.opts.firewallUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${await this.opts.getToken()}`, "content-type": "application/json" },
        body: JSON.stringify(body)
      });
    } catch (err) {
      this.fail(`unreachable (${err.message})`);
      return null;
    }
    if (!res.ok) {
      this.fail(`HTTP ${res.status}`);
      return null;
    }
    this.pendingResults = this.pendingResults.filter((r) => !results.includes(r));
    if (this.down) {
      this.log("[firewall] control channel back");
      this.down = false;
    }
    this.backoffMs = 0;
    const data = await res.json().catch(() => ({}));
    const c = data.command;
    if (!c || typeof c.id !== "string" || typeof c.action !== "string") return null;
    const payload = c.payload && typeof c.payload === "object" ? c.payload : {};
    return { id: c.id, action: c.action, payload };
  }
  async runService(id, action) {
    this.log(`[firewall] ${action} ${this.service} (command ${id})`);
    try {
      this.exec(`sudo systemctl ${action} ${this.service}`, this.actionTimeoutMs);
      const status = this.proxyStatus();
      const ok = action === "stop" ? status !== "active" : status === "active";
      return { command_id: id, ok, status, message: ok ? "" : `service is ${status} after ${action}` };
    } catch (err) {
      const e = err;
      const message2 = (e.stderr ? String(e.stderr) : e.message ?? "exec failed").trim().slice(0, 500);
      this.log(`[firewall] ${action} failed: ${message2}`);
      return { command_id: id, ok: false, status: this.proxyStatus(), message: message2 };
    }
  }
  fail(reason) {
    this.backoffMs = Math.min(this.backoffMs ? this.backoffMs * 2 : 5e3, 6e4);
    this.nextAttemptAt = Date.now() + this.backoffMs;
    if (!this.down) {
      this.log(`[firewall] control channel down: ${reason}; retrying`);
      this.down = true;
    }
  }
};

// src/consent-codes.ts
import { createHash, randomInt, timingSafeEqual } from "crypto";
var CODE_TTL_MS = 10 * 6e4;
var CODE_ATTEMPTS = 5;
function codeMessage(agentName, summary, code) {
  const pretty = `${code.slice(0, 3)} ${code.slice(3)}`;
  return `ControlClaw: confirm this change to ${agentName}?
${summary}
Code: ${pretty}
Expires in 10 minutes. If you did not ask for this, ignore it and check your ControlClaw console.`;
}
function sha256(s) {
  return createHash("sha256").update(s).digest("hex");
}
var ConsentCodes = class {
  constructor(opts) {
    this.opts = opts;
    this.log = opts.log ?? ((l) => console.log(l));
    this.now = opts.now ?? Date.now;
    this.makeCode = opts.makeCode ?? (() => String(randomInt(0, 1e6)).padStart(6, "0"));
  }
  pending = /* @__PURE__ */ new Map();
  log;
  now;
  makeCode;
  /**
   * Mint a code and have an agent deliver it to the first sender that can be reached, trying the
   * routes in order. `agentName` is what the message names as the thing being changed.
   */
  async send(scope, proposal, agentName, summary, routes) {
    const code = this.makeCode();
    const text = codeMessage(agentName, summary, code);
    let sentVia = null;
    let lastError = "";
    for (const route of routes) {
      for (const sender of route.senders) {
        try {
          await this.opts.agent.post(route.target, "/channels/send", { type: sender.type, to: sender.id, text });
          sentVia = `${sender.type}:${sender.label ?? sender.id}`;
          break;
        } catch (err) {
          lastError = err.message;
          this.log(`[codes] could not send the code via ${sender.type} on ${route.target.hostname}: ${lastError}`);
        }
      }
      if (sentVia) break;
    }
    if (!sentVia) {
      return {
        ok: false,
        message: `Could not reach you on any connected channel (${lastError || "no sender answered"}). Make sure the agent is running, then try again.`
      };
    }
    const expiresAt = this.now() + CODE_TTL_MS;
    this.pending.set(scope, { proposal, codeHash: sha256(code), attemptsLeft: CODE_ATTEMPTS, expiresAt, sentVia });
    return { ok: true, sentVia, expiresAt: new Date(expiresAt).toISOString(), attemptsLeft: CODE_ATTEMPTS };
  }
  /** Constant-time check; a wrong code counts down, the last wrong one drops the proposal. */
  verify(scope, changeId, code) {
    const pending = this.pending.get(scope);
    if (!pending || pending.proposal.changeId !== changeId) return { kind: "expired" };
    if (this.now() > pending.expiresAt) {
      this.pending.delete(scope);
      return { kind: "expired" };
    }
    const given = Buffer.from(sha256(code.replace(/\s+/g, "")));
    const want = Buffer.from(pending.codeHash);
    if (given.length !== want.length || !timingSafeEqual(given, want)) {
      pending.attemptsLeft -= 1;
      if (pending.attemptsLeft <= 0) this.pending.delete(scope);
      return { kind: "invalid", attemptsLeft: pending.attemptsLeft };
    }
    this.pending.delete(scope);
    return { kind: "ok", proposal: pending.proposal, sentVia: pending.sentVia };
  }
  /** True when that change was the pending one (and is now dropped). */
  cancel(scope, changeId) {
    const pending = this.pending.get(scope);
    if (!pending || pending.proposal.changeId !== changeId) return false;
    this.pending.delete(scope);
    return true;
  }
  drop(scope) {
    this.pending.delete(scope);
  }
};

// src/enc-file.ts
import { createCipheriv as createCipheriv2, createDecipheriv as createDecipheriv2, randomBytes as randomBytes2 } from "crypto";
import { existsSync as existsSync4, mkdirSync as mkdirSync3, readFileSync as readFileSync5, renameSync, writeFileSync as writeFileSync4 } from "fs";
import { dirname as dirname2 } from "path";
var NONCE_BYTES2 = 12;
var TAG_BYTES2 = 16;
function encryptJson(value, boxKeyB64, aad4) {
  const key = Buffer.from(boxKeyB64, "base64");
  const nonce = randomBytes2(NONCE_BYTES2);
  const cipher = createCipheriv2("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(aad4, "utf8"));
  const ct = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(value), "utf8")), cipher.final(), cipher.getAuthTag()]);
  return JSON.stringify({ alg: "AES-256-GCM", nonce: nonce.toString("base64"), ct: ct.toString("base64") });
}
function decryptJson(raw, boxKeyB64, aad4) {
  const { nonce, ct } = JSON.parse(raw);
  const key = Buffer.from(boxKeyB64, "base64");
  const buf = Buffer.from(ct, "base64");
  const decipher = createDecipheriv2("aes-256-gcm", key, Buffer.from(nonce, "base64"));
  decipher.setAAD(Buffer.from(aad4, "utf8"));
  decipher.setAuthTag(buf.subarray(buf.length - TAG_BYTES2));
  const pt = Buffer.concat([decipher.update(buf.subarray(0, buf.length - TAG_BYTES2)), decipher.final()]);
  return JSON.parse(pt.toString("utf8"));
}
function loadEncryptedJson(path, boxKeyB64, aad4) {
  if (!existsSync4(path)) return null;
  return decryptJson(readFileSync5(path, "utf8"), boxKeyB64, aad4);
}
function saveEncryptedJson(path, value, boxKeyB64, aad4) {
  mkdirSync3(dirname2(path), { recursive: true });
  const tmp = `${path}.tmp`;
  writeFileSync4(tmp, encryptJson(value, boxKeyB64, aad4), { mode: 384 });
  renameSync(tmp, path);
}

// src/channel-store.ts
function aad2(ids2) {
  return `${ids2.orgId}:${ids2.boxId}:channels`;
}
function coerce(parsed) {
  return parsed && parsed.version === 1 && parsed.agents ? parsed : { version: 1, agents: {} };
}
function loadChannelStore(path, boxKeyB64, ids2) {
  return coerce(loadEncryptedJson(path, boxKeyB64, aad2(ids2)));
}
function saveChannelStore(path, store, boxKeyB64, ids2) {
  saveEncryptedJson(path, store, boxKeyB64, aad2(ids2));
}

// src/channels.ts
var NAMES = { telegram: "Telegram", slack: "Slack", whatsapp: "WhatsApp" };
function summarize(p) {
  const name = NAMES[p.type];
  switch (p.kind) {
    case "add":
      return `Add a ${name} bot (${p.hint ?? "token"})`;
    case "replace":
      return `Replace the ${name} token (${p.hint ?? "new token"})`;
    case "remove":
      return `Remove ${name}`;
    case "approve_pairing":
      return `Approve ${name} sender ${p.pairing?.label ? `${p.pairing.label} (${p.pairing.senderId})` : p.pairing?.senderId ?? "?"}`;
    case "whatsapp_login":
      return p.settings?.personal ? "Connect WhatsApp by QR (personal number)" : "Connect WhatsApp by QR";
  }
}
function placeholderFor(type, vmId, which = "bot") {
  return `__cc_${type}_${which}_${vmId}`;
}
function isKind(v) {
  return v === "add" || v === "replace" || v === "remove" || v === "approve_pairing" || v === "whatsapp_login";
}
function isType(v) {
  return v === "telegram" || v === "slack" || v === "whatsapp";
}
function str(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function parseProposal(payload) {
  const changeId = str(payload.changeId);
  const vmId = str(payload.vmId);
  const hostname = str(payload.hostname);
  if (!changeId || !vmId || !hostname || !isKind(payload.kind) || !isType(payload.type)) {
    throw new Error("malformed channels.propose payload");
  }
  const pairing = payload.pairing;
  const settings = payload.settings;
  const secret = payload.secret;
  return {
    changeId,
    vmId,
    agentName: str(payload.agentName) ?? vmId,
    hostname,
    kind: payload.kind,
    type: payload.type,
    hint: str(payload.hint),
    label: str(payload.label),
    ...pairing && str(pairing.code) && str(pairing.senderId) ? { pairing: { code: String(pairing.code), senderId: String(pairing.senderId), label: str(pairing.label) } } : {},
    ...settings ? { settings: { personal: settings.personal === true } } : {},
    ...secret ? { secret: { botToken: str(secret.botToken) ?? void 0, appToken: str(secret.appToken) ?? void 0 } } : {}
  };
}
var ChannelsFirewall = class {
  constructor(opts) {
    this.opts = opts;
    this.log = opts.log ?? ((l) => console.log(l));
    this.now = opts.now ?? Date.now;
    this.codes = new ConsentCodes({ agent: opts.agent, log: this.log, now: this.now, makeCode: opts.makeCode });
    this.store = loadChannelStore(opts.storePath, opts.boxKey, opts.ids);
  }
  store;
  // One pending code per agent (scope = vmId).
  codes;
  log;
  now;
  /**
   * Every agent someone is approved to talk to, as code routes: the LLM firewall sends its
   * codes through the same people, since an org-level change has no single agent of its own.
   */
  codeRoutes() {
    const out = [];
    for (const [vmId, agent] of Object.entries(this.store.agents)) {
      if (agent.approvedSenders.length === 0) continue;
      let target;
      try {
        target = this.target(vmId, agent.hostname);
      } catch {
        continue;
      }
      out.push({ target, senders: agent.approvedSenders, agentName: agent.name });
    }
    return out;
  }
  handlers() {
    return {
      "channels.propose": (p) => this.propose(p),
      "channels.confirm": (p) => this.confirm(p),
      "channels.cancel": (p) => this.cancel(p),
      "channels.push": (p) => this.push(p)
    };
  }
  /** Proxy credential entries for placeholder-mode channels (merged into credentials.json). */
  credentials() {
    if (!this.opts.placeholderSwap) return [];
    const out = [];
    for (const [vmId, agent] of Object.entries(this.store.agents)) {
      const tg = agent.channels.telegram;
      if (tg?.secrets.botToken) {
        out.push({ placeholder: placeholderFor("telegram", vmId), match_domain: "api.telegram.org", secret: tg.secrets.botToken, locations: ["path"], vm_id: vmId });
      }
      const sl = agent.channels.slack;
      if (sl?.secrets.botToken) {
        out.push({ placeholder: placeholderFor("slack", vmId, "bot"), match_domain: "slack.com", secret: sl.secrets.botToken, locations: ["header:authorization"], vm_id: vmId });
      }
      if (sl?.secrets.appToken) {
        out.push({ placeholder: placeholderFor("slack", vmId, "app"), match_domain: "slack.com", secret: sl.secrets.appToken, locations: ["header:authorization"], vm_id: vmId });
      }
    }
    return out;
  }
  /** What the console may see: no secrets. */
  summary() {
    const out = [];
    for (const [vmId, agent] of Object.entries(this.store.agents)) {
      for (const [type, ch] of Object.entries(agent.channels)) {
        if (ch) out.push({ vmId, type, hint: ch.hint, approvedSenders: agent.approvedSenders.length });
      }
    }
    return out;
  }
  save() {
    saveChannelStore(this.opts.storePath, this.store, this.opts.boxKey, this.opts.ids);
  }
  agentOf(vmId, name, hostname) {
    let a = this.store.agents[vmId];
    if (!a) {
      a = { name: name ?? vmId, hostname: hostname ?? null, channels: {}, approvedSenders: [] };
      this.store.agents[vmId] = a;
    }
    if (name) a.name = name;
    if (hostname) a.hostname = hostname;
    return a;
  }
  target(vmId, hostname) {
    const known = this.opts.identities().find((i) => i.vm_id === vmId);
    const host = hostname ?? known?.hostname ?? this.store.agents[vmId]?.hostname ?? null;
    if (!host) throw new Error("This agent has no hostname yet.");
    return { vmId, hostname: host };
  }
  // ---- commands ----
  async propose(payload) {
    const p = parseProposal(payload);
    const agent = this.agentOf(p.vmId, p.agentName, p.hostname);
    const summary = summarize(p);
    const data = { changeId: p.changeId, summary };
    if (agent.approvedSenders.length === 0) {
      this.codes.drop(p.vmId);
      const applied = await this.apply(p);
      return { ok: true, status: "applied", data: { ...data, ...applied, tofu: true } };
    }
    const target = this.target(p.vmId, p.hostname);
    const sent = await this.codes.send(p.vmId, p, p.agentName, summary, [{ target, senders: agent.approvedSenders }]);
    if (!sent.ok) return { ok: false, status: "failed", message: sent.message, data };
    this.log(`[channels] code sent for ${p.kind} ${p.type} on ${p.agentName} via ${sent.sentVia}`);
    return {
      ok: true,
      status: "awaiting_code",
      data: { ...data, sentVia: sent.sentVia, expiresAt: sent.expiresAt, attemptsLeft: sent.attemptsLeft }
    };
  }
  async confirm(payload) {
    const changeId = str(payload.changeId);
    const vmId = str(payload.vmId);
    const code = str(payload.code)?.replace(/\s+/g, "") ?? "";
    if (!changeId || !vmId) throw new Error("malformed channels.confirm payload");
    const data = { changeId };
    const v = this.codes.verify(vmId, changeId, code);
    if (v.kind === "expired") return { ok: false, status: "expired", message: "No change is waiting for a code, or the code expired.", data };
    if (v.kind === "invalid") return { ok: false, status: "invalid_code", message: "Wrong code.", data: { ...data, attemptsLeft: v.attemptsLeft } };
    const applied = await this.apply(v.proposal);
    return { ok: true, status: "applied", data: { ...data, ...applied, summary: summarize(v.proposal), sentVia: v.sentVia, tofu: false } };
  }
  async cancel(payload) {
    const changeId = str(payload.changeId);
    const vmId = str(payload.vmId);
    if (vmId) this.codes.cancel(vmId, changeId);
    return { ok: true, status: "cancelled", data: { changeId } };
  }
  async push(payload) {
    const vmId = str(payload.vmId);
    if (!vmId) throw new Error("malformed channels.push payload");
    const agent = this.store.agents[vmId];
    if (!agent) return { ok: true, status: "applied", data: { vmId, applied: [], failed: [] } };
    if (str(payload.hostname)) agent.hostname = String(payload.hostname);
    const target = this.target(vmId, agent.hostname);
    const applied = [];
    const failed = [];
    for (const [type, ch] of Object.entries(agent.channels)) {
      if (!ch) continue;
      try {
        await this.opts.agent.post(target, "/channels/apply", this.applyBody(vmId, type, ch.secrets, ch.settings));
        applied.push(type);
      } catch (err) {
        failed.push({ type, error: err.message });
      }
    }
    this.log(`[channels] re-applied ${applied.length} channel(s) on ${agent.name}${failed.length ? `, ${failed.length} failed` : ""}`);
    return { ok: failed.length === 0, status: failed.length ? "failed" : "applied", message: failed.map((f) => `${f.type}: ${f.error}`).join("; "), data: { vmId, applied, failed } };
  }
  // ---- applying ----
  applyBody(vmId, type, secrets, settings) {
    if (type === "whatsapp") return { type, settings };
    if (!this.opts.placeholderSwap) return { type, secrets };
    const swapped = {};
    if (secrets.botToken) swapped.botToken = placeholderFor(type, vmId, "bot");
    if (secrets.appToken) swapped.appToken = placeholderFor(type, vmId, "app");
    return { type, secrets: swapped };
  }
  async apply(p) {
    const agent = this.agentOf(p.vmId, p.agentName, p.hostname);
    const target = this.target(p.vmId, p.hostname);
    const mode = this.opts.placeholderSwap && p.type !== "whatsapp" ? "placeholder" : "plain";
    switch (p.kind) {
      case "add":
      case "replace": {
        if (!p.secret?.botToken) throw new Error("no token in the proposal");
        if (p.type === "slack" && !p.secret.appToken) throw new Error("Slack needs both a bot token and an app token");
        const secrets = { botToken: p.secret.botToken, ...p.secret.appToken ? { appToken: p.secret.appToken } : {} };
        agent.channels[p.type] = { secrets, settings: {}, hint: p.hint, label: p.label, updatedAt: new Date(this.now()).toISOString() };
        this.save();
        await this.opts.onCredentialsChanged?.();
        await this.opts.agent.post(target, "/channels/apply", this.applyBody(p.vmId, p.type, secrets, {}));
        return { mode };
      }
      case "remove": {
        await this.opts.agent.post(target, "/channels/apply", { type: p.type, remove: true });
        delete agent.channels[p.type];
        agent.approvedSenders = agent.approvedSenders.filter((s) => s.type !== p.type);
        this.save();
        await this.opts.onCredentialsChanged?.();
        return {};
      }
      case "approve_pairing": {
        if (!p.pairing) throw new Error("no pairing in the proposal");
        const r = await this.opts.agent.post(target, "/channels/pairings/approve", { type: p.type, code: p.pairing.code });
        const id = str(r.senderId) ?? p.pairing.senderId;
        const sender = { type: p.type, id, label: p.pairing.label, at: new Date(this.now()).toISOString() };
        if (!agent.approvedSenders.some((s) => s.type === sender.type && s.id === sender.id)) agent.approvedSenders.push(sender);
        this.save();
        return { approvedSender: `${sender.type}:${sender.label ?? sender.id}` };
      }
      case "whatsapp_login": {
        const settings = { personal: p.settings?.personal === true };
        const r = await this.opts.agent.post(target, "/channels/whatsapp/login", settings);
        agent.channels.whatsapp = { secrets: {}, settings, hint: null, label: p.label, updatedAt: new Date(this.now()).toISOString() };
        this.save();
        return { mode: "plain", whatsapp: { state: r.state ?? "qr" } };
      }
    }
  }
};

// src/llm-store.ts
function aad3(ids2) {
  return `${ids2.orgId}:${ids2.boxId}:llm`;
}
function emptyLlmStore() {
  return { version: 1, credentials: {}, agents: {} };
}
function loadLlmStore(path, boxKeyB64, ids2) {
  const parsed = loadEncryptedJson(path, boxKeyB64, aad3(ids2));
  return parsed && parsed.version === 1 && parsed.credentials && parsed.agents ? parsed : emptyLlmStore();
}
function saveLlmStore(path, store, boxKeyB64, ids2) {
  saveEncryptedJson(path, store, boxKeyB64, aad3(ids2));
}

// src/llm.ts
var REFRESH_AHEAD_MS = 15 * 6e4;
var REFRESH_TIMEOUT_MS = 3e4;
var SCOPE = "org";
function str2(v) {
  return typeof v === "string" && v.length > 0 ? v : null;
}
function isKind2(v) {
  return v === "add" || v === "replace" || v === "remove" || v === "bind" || v === "unbind" || v === "set_model";
}
function modelShort(model) {
  return model.includes("/") ? model.slice(model.indexOf("/") + 1) : model;
}
function summarize2(p) {
  const a = p.agents[0];
  switch (p.kind) {
    case "add":
      return p.credKind === "oauth" ? `Connect ${p.providerName} (${p.label ?? p.hint ?? "account"})` : `Add ${p.providerName} key (${p.hint ?? "key"})`;
    case "replace":
      return p.credKind === "oauth" ? `Reconnect ${p.providerName} (${p.label ?? p.hint ?? "account"})` : `Replace the ${p.providerName} key (${p.hint ?? "new key"})`;
    case "remove":
      return `Remove ${p.providerName} from the organization`;
    case "bind":
      return `Use ${p.providerName} ${a ? modelShort(a.model) : ""} on ${a?.name ?? "the agent"}${a?.isPrimary ? " as the main model" : ""}`.replace(/\s+/g, " ");
    case "set_model":
      return `Switch ${a?.name ?? "the agent"} to ${p.providerName} ${a ? modelShort(a.model) : ""}`.trim();
    case "unbind":
      return `Stop using ${p.providerName} on ${a?.name ?? "the agent"}`;
  }
}
function parseSecret(secret) {
  if (!secret) return void 0;
  if (str2(secret.apiKey)) return { apiKey: String(secret.apiKey) };
  if (str2(secret.token)) return { token: String(secret.token) };
  const o = secret.oauth;
  if (o && str2(o.access) && str2(o.refresh)) {
    return {
      access: String(o.access),
      refresh: String(o.refresh),
      expires: typeof o.expires === "number" ? o.expires : 0,
      accountId: str2(o.accountId),
      email: str2(o.email)
    };
  }
  return void 0;
}
function parseProposal2(payload) {
  const changeId = str2(payload.changeId);
  const credentialId = str2(payload.credentialId);
  const provider = str2(payload.provider);
  if (!changeId || !credentialId || !provider || !isKind2(payload.kind)) throw new Error("malformed llm.propose payload");
  const swap = payload.swap;
  const oauth = payload.oauth;
  const agents = Array.isArray(payload.agents) ? payload.agents : [];
  const credKind = payload.credKind;
  return {
    changeId,
    kind: payload.kind,
    credentialId,
    provider,
    providerName: str2(payload.providerName) ?? provider,
    credKind: credKind === "api_key" || credKind === "token" || credKind === "oauth" ? credKind : null,
    placeholder: str2(payload.placeholder),
    hint: str2(payload.hint),
    label: str2(payload.label),
    profileId: str2(payload.profileId),
    swap: swap && str2(swap.matchDomain) && Array.isArray(swap.locations) ? { matchDomain: String(swap.matchDomain), locations: swap.locations.map(String) } : null,
    oauth: oauth && str2(oauth.tokenEndpoint) && str2(oauth.clientId) ? { tokenEndpoint: String(oauth.tokenEndpoint), clientId: String(oauth.clientId) } : null,
    agents: agents.filter((a) => str2(a.vmId) && str2(a.model)).map((a) => ({ vmId: String(a.vmId), name: str2(a.name) ?? String(a.vmId), hostname: str2(a.hostname), model: String(a.model), isPrimary: a.isPrimary === true })),
    secret: parseSecret(payload.secret)
  };
}
function secretValue(s) {
  if ("apiKey" in s) return s.apiKey;
  if ("token" in s) return s.token;
  return s.access;
}
var LlmFirewall = class {
  constructor(opts) {
    this.opts = opts;
    this.log = opts.log ?? ((l) => console.log(l));
    this.now = opts.now ?? Date.now;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.codes = new ConsentCodes({ agent: opts.agent, log: this.log, now: this.now, makeCode: opts.makeCode });
    this.store = loadLlmStore(opts.storePath, opts.boxKey, opts.ids);
  }
  store;
  codes;
  log;
  now;
  fetchImpl;
  reports = [];
  refreshing = false;
  handlers() {
    return {
      "llm.propose": (p) => this.propose(p),
      "llm.confirm": (p) => this.confirm(p),
      "llm.cancel": (p) => this.cancel(p),
      "llm.push": (p) => this.push(p)
    };
  }
  /** Proxy credential entries: one per agent binding, swapped only on that agent's traffic. */
  credentials() {
    const out = [];
    for (const [vmId, agent] of Object.entries(this.store.agents)) {
      for (const b of agent.bindings) {
        const c = this.store.credentials[b.credentialId];
        if (!c) continue;
        if (this.opts.plainKeys && c.kind !== "oauth") continue;
        out.push({ placeholder: c.placeholder, match_domain: c.swap.matchDomain, secret: secretValue(c.secret), locations: c.swap.locations, vm_id: vmId });
      }
    }
    return out;
  }
  /** What the console may see: no secrets. */
  summary() {
    return {
      credentials: Object.entries(this.store.credentials).map(([id, c]) => ({ id, provider: c.provider, kind: c.kind, hint: c.hint, failed: c.failed })),
      agents: Object.keys(this.store.agents).length
    };
  }
  /** Reports made outside a command (refresh failures), drained by the heartbeat. */
  drainReports() {
    const r = this.reports;
    this.reports = [];
    return r;
  }
  save() {
    saveLlmStore(this.opts.storePath, this.store, this.opts.boxKey, this.opts.ids);
  }
  agentOf(ref) {
    let a = this.store.agents[ref.vmId];
    if (!a) {
      a = { name: ref.name, hostname: ref.hostname, bindings: [] };
      this.store.agents[ref.vmId] = a;
    }
    if (ref.name) a.name = ref.name;
    if (ref.hostname) a.hostname = ref.hostname;
    return a;
  }
  target(vmId) {
    const host = this.store.agents[vmId]?.hostname ?? null;
    if (!host) throw new Error("This agent has no hostname yet.");
    return { vmId, hostname: host };
  }
  // ---- commands ----
  async propose(payload) {
    const p = parseProposal2(payload);
    const summary = summarize2(p);
    const data = { changeId: p.changeId, summary };
    const routes = this.opts.codeRoutes();
    if (routes.length === 0) {
      this.codes.drop(SCOPE);
      const applied = await this.apply(p);
      return { ok: true, status: "applied", data: { ...data, ...applied, tofu: true } };
    }
    const sent = await this.codes.send(SCOPE, p, "your organization's model providers", summary, routes);
    if (!sent.ok) return { ok: false, status: "failed", message: sent.message, data };
    this.log(`[llm] code sent for ${p.kind} ${p.provider} via ${sent.sentVia}`);
    return { ok: true, status: "awaiting_code", data: { ...data, sentVia: sent.sentVia, expiresAt: sent.expiresAt, attemptsLeft: sent.attemptsLeft } };
  }
  async confirm(payload) {
    const changeId = str2(payload.changeId);
    const code = str2(payload.code) ?? "";
    if (!changeId) throw new Error("malformed llm.confirm payload");
    const data = { changeId };
    const v = this.codes.verify(SCOPE, changeId, code);
    if (v.kind === "expired") return { ok: false, status: "expired", message: "No change is waiting for a code, or the code expired.", data };
    if (v.kind === "invalid") return { ok: false, status: "invalid_code", message: "Wrong code.", data: { ...data, attemptsLeft: v.attemptsLeft } };
    const applied = await this.apply(v.proposal);
    return { ok: true, status: "applied", data: { ...data, ...applied, summary: summarize2(v.proposal), sentVia: v.sentVia, tofu: false } };
  }
  async cancel(payload) {
    const changeId = str2(payload.changeId);
    this.codes.cancel(SCOPE, changeId);
    return { ok: true, status: "cancelled", data: { changeId } };
  }
  async push(payload) {
    const vmId = str2(payload.vmId);
    if (!vmId) throw new Error("malformed llm.push payload");
    const agent = this.store.agents[vmId];
    if (!agent || agent.bindings.length === 0) return { ok: true, status: "applied", data: { vmId, applied: [], failed: [] } };
    if (str2(payload.hostname)) agent.hostname = String(payload.hostname);
    if (str2(payload.name)) agent.name = String(payload.name);
    this.save();
    const failed = await this.pushAgents([vmId], []);
    this.log(`[llm] re-applied ${agent.bindings.length} provider(s) on ${agent.name}${failed.length ? ` (failed: ${failed[0].error})` : ""}`);
    return {
      ok: failed.length === 0,
      status: failed.length ? "failed" : "applied",
      message: failed.map((f) => f.error).join("; "),
      data: { vmId, applied: failed.length ? [] : agent.bindings.map((b) => b.credentialId), failed }
    };
  }
  // ---- applying ----
  /** The whole desired state of one agent box. */
  applyBody(vmId, remove) {
    const agent = this.store.agents[vmId];
    const bindings = agent?.bindings ?? [];
    const credentials = bindings.map((b) => ({ b, c: this.store.credentials[b.credentialId] })).filter((x) => !!x.c).map(({ b, c }) => ({
      provider: c.provider,
      kind: c.kind,
      profileId: c.profileId,
      value: this.opts.plainKeys && c.kind !== "oauth" ? secretValue(c.secret) : c.placeholder,
      model: b.model,
      ..."accountId" in c.secret && c.secret.accountId ? { codex: { accountId: c.secret.accountId } } : {}
    }));
    const primary = bindings.find((b) => b.isPrimary)?.model ?? bindings[0]?.model ?? null;
    const fallbacks = bindings.map((b) => b.model).filter((m) => m !== primary);
    return { model: { primary, fallbacks }, credentials, remove };
  }
  async pushAgents(vmIds, remove) {
    const failed = [];
    for (const vmId of vmIds) {
      try {
        await this.opts.agent.post(this.target(vmId), "/llm/apply", this.applyBody(vmId, remove));
      } catch (err) {
        failed.push({ vmId, error: err.message });
      }
    }
    return failed;
  }
  setBinding(ref, credentialId) {
    const agent = this.agentOf(ref);
    const others = agent.bindings.filter((b) => b.credentialId !== credentialId);
    if (ref.isPrimary) for (const o of others) o.isPrimary = false;
    const isPrimary = ref.isPrimary || others.every((o) => !o.isPrimary);
    agent.bindings = [...others, { credentialId, model: ref.model, isPrimary }];
  }
  dropBinding(vmId, credentialId) {
    const agent = this.store.agents[vmId];
    if (!agent) return;
    agent.bindings = agent.bindings.filter((b) => b.credentialId !== credentialId);
    if (agent.bindings.length && !agent.bindings.some((b) => b.isPrimary)) agent.bindings[0].isPrimary = true;
  }
  boundAgents(credentialId) {
    return Object.entries(this.store.agents).filter(([, a]) => a.bindings.some((b) => b.credentialId === credentialId)).map(([vmId]) => vmId);
  }
  async apply(p) {
    const mode = this.opts.plainKeys && p.credKind !== "oauth" ? "plain" : "placeholder";
    const existing = this.store.credentials[p.credentialId];
    switch (p.kind) {
      case "add":
      case "replace": {
        if (!p.secret) throw new Error("no secret in the proposal");
        if (!p.placeholder || !p.profileId || !p.swap || !p.credKind) throw new Error("the proposal is missing the placeholder, profile id or swap location");
        if (p.credKind === "oauth" && !p.oauth) throw new Error("an OAuth credential needs its token endpoint");
        this.store.credentials[p.credentialId] = {
          provider: p.provider,
          kind: p.credKind,
          placeholder: p.placeholder,
          hint: p.hint,
          label: p.label,
          profileId: p.profileId,
          swap: p.swap,
          ...p.oauth ? { oauth: p.oauth } : {},
          secret: p.secret,
          failed: null,
          updatedAt: new Date(this.now()).toISOString()
        };
        for (const a of p.agents) this.setBinding(a, p.credentialId);
        this.save();
        await this.opts.onCredentialsChanged?.();
        const targets = /* @__PURE__ */ new Set([...this.boundAgents(p.credentialId), ...p.agents.map((a) => a.vmId)]);
        const failed = await this.pushAgents([...targets], []);
        return { mode, applied: [...targets].filter((v) => !failed.some((f) => f.vmId === v)), failed };
      }
      case "remove": {
        const bound = this.boundAgents(p.credentialId);
        const remove = existing ? [{ provider: existing.provider, profileId: existing.profileId, kind: existing.kind }] : [];
        for (const vmId of bound) this.dropBinding(vmId, p.credentialId);
        delete this.store.credentials[p.credentialId];
        this.save();
        await this.opts.onCredentialsChanged?.();
        const failed = await this.pushAgents(bound, remove);
        return { applied: bound.filter((v) => !failed.some((f) => f.vmId === v)), failed };
      }
      case "bind":
      case "set_model": {
        if (!existing) throw new Error("This provider is not set up on the firewall. Add it again.");
        const a = p.agents[0];
        if (!a) throw new Error("no agent in the proposal");
        this.setBinding(a, p.credentialId);
        this.save();
        await this.opts.onCredentialsChanged?.();
        const failed = await this.pushAgents([a.vmId], []);
        return { mode, applied: failed.length ? [] : [a.vmId], failed };
      }
      case "unbind": {
        const a = p.agents[0];
        if (!a) throw new Error("no agent in the proposal");
        this.dropBinding(a.vmId, p.credentialId);
        this.save();
        await this.opts.onCredentialsChanged?.();
        const remove = existing ? [{ provider: existing.provider, profileId: existing.profileId, kind: existing.kind }] : [];
        const failed = await this.pushAgents([a.vmId], remove);
        return { applied: failed.length ? [] : [a.vmId], failed };
      }
    }
  }
  // ---- OAuth refresh ----
  /** Refresh every OAuth credential that expires within REFRESH_AHEAD_MS. Called on a timer. */
  async refreshDue() {
    if (this.refreshing) return;
    this.refreshing = true;
    try {
      let changed = false;
      for (const [id, c] of Object.entries(this.store.credentials)) {
        if (c.kind !== "oauth" || !c.oauth || !("refresh" in c.secret) || c.failed) continue;
        if (c.secret.expires - this.now() > REFRESH_AHEAD_MS) continue;
        const r = await this.refreshOne(id, c);
        if (r) changed = true;
      }
      if (changed) {
        this.save();
        await this.opts.onCredentialsChanged?.();
      }
    } finally {
      this.refreshing = false;
    }
  }
  async refreshOne(id, c) {
    if (!c.oauth || !("refresh" in c.secret)) return false;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REFRESH_TIMEOUT_MS);
    try {
      const res = await this.fetchImpl(c.oauth.tokenEndpoint, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: c.secret.refresh, client_id: c.oauth.clientId }).toString(),
        signal: controller.signal
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok || typeof body.access_token !== "string") {
        const reason = str2(body.error_description) ?? str2(body.error) ?? `HTTP ${res.status}`;
        if (res.status >= 400 && res.status < 500) {
          c.failed = `Token refresh refused: ${reason}. Connect the account again.`;
          this.reports.push({ command_id: `llm.refresh:${id}`, ok: false, status: "failed", message: c.failed, data: { credentialId: id } });
          this.log(`[llm] refresh of ${c.provider} refused: ${reason}`);
          return true;
        }
        this.log(`[llm] refresh of ${c.provider} failed (${reason}); will retry`);
        return false;
      }
      const expiresIn = typeof body.expires_in === "number" ? body.expires_in : 3600;
      c.secret = {
        ...c.secret,
        access: body.access_token,
        refresh: typeof body.refresh_token === "string" && body.refresh_token ? body.refresh_token : c.secret.refresh,
        expires: this.now() + expiresIn * 1e3
      };
      c.updatedAt = new Date(this.now()).toISOString();
      this.log(`[llm] refreshed ${c.provider} token (expires in ${Math.round(expiresIn / 60)} min)`);
      return true;
    } catch (err) {
      this.log(`[llm] refresh of ${c.provider} errored (${err.message}); will retry`);
      return false;
    } finally {
      clearTimeout(timer);
    }
  }
};

// src/agent-client.ts
import { readFileSync as readFileSync6 } from "fs";
var AGENT_PATH_PREFIX = "/__cc/agent";
var TIMEOUT_MS = 25e3;
function purposeForPath(path) {
  return path.startsWith("/llm/") ? "llm" : "channels";
}
function makeAgentTokenSigner(keysDir, boxId) {
  const read = (name) => readFileSync6(`${keysDir}/${name}`, "utf-8").trim();
  return async (agentVmId, purpose = "channels") => {
    const key = await importPKCS8(read("vm_private_key.pem"), "EdDSA");
    return new SignJWT({ vmId: agentVmId, purpose, iss: boxId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
  };
}
function makeAgentClient(opts) {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? TIMEOUT_MS;
  async function request(agent, method, path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetchImpl(`https://${agent.hostname}${AGENT_PATH_PREFIX}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${await opts.sign(agent.vmId, purposeForPath(path))}`,
          ...body ? { "content-type": "application/json" } : {}
        },
        body: body ? JSON.stringify(body) : void 0,
        signal: controller.signal
      });
      const text = await res.text();
      let parsed = {};
      try {
        parsed = text ? JSON.parse(text) : {};
      } catch {
        parsed = {};
      }
      if (!res.ok) {
        const detail = typeof parsed.error === "string" ? parsed.error : text.slice(0, 200);
        throw new Error(res.status === 503 ? "The agent is not running. Start it and try again." : `agent ${res.status}: ${detail}`);
      }
      return parsed;
    } catch (err) {
      if (err.name === "AbortError") throw new Error("The agent did not answer in time.");
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
  return {
    post: (agent, path, body) => request(agent, "POST", path, body),
    get: (agent, path) => request(agent, "GET", path)
  };
}

// src/sync.ts
import { writeFileSync as writeFileSync5, mkdirSync as mkdirSync4, renameSync as renameSync2 } from "fs";
import { join } from "path";
function decryptToConfig(record, boxKey, ids2) {
  const plaintext = openWithBoxKey(record, boxKey, ids2);
  const cfg = JSON.parse(plaintext);
  return cfg;
}
function writeProxyConfig(dir, cfg) {
  mkdirSync4(dir, { recursive: true });
  const writeAtomic = (name, data) => {
    const tmp = join(dir, `.${name}.tmp`);
    const dst = join(dir, name);
    writeFileSync5(tmp, JSON.stringify(data, null, 2), { mode: 384 });
    renameSync2(tmp, dst);
  };
  writeAtomic("credentials.json", cfg.credentials ?? []);
  writeAtomic("rules.json", cfg.rules ?? []);
  writeAtomic("identities.json", cfg.identities ?? []);
}

// src/permissions.ts
import { readFileSync as readFileSync7, writeFileSync as writeFileSync6, existsSync as existsSync5 } from "fs";
var PermissionBridge = class {
  constructor(opts) {
    this.opts = opts;
    if (existsSync5(opts.grantsPath)) {
      try {
        this.grants = JSON.parse(readFileSync7(opts.grantsPath, "utf8"));
      } catch {
        this.grants = {};
      }
    }
  }
  submitted = /* @__PURE__ */ new Set();
  meta = /* @__PURE__ */ new Map();
  grants = {};
  async authHeaders(extra = {}) {
    return { Authorization: `Bearer ${await this.opts.getToken()}`, ...extra };
  }
  async tick() {
    await this.drainPending();
    await this.pollGrants();
  }
  /** Submit any new pending permission requests to ControlClaw (idempotent). */
  async drainPending() {
    if (!existsSync5(this.opts.pendingPath)) return;
    const lines = readFileSync7(this.opts.pendingPath, "utf8").split("\n").filter(Boolean);
    for (const line of lines) {
      let rec;
      try {
        rec = JSON.parse(line);
      } catch {
        continue;
      }
      if (!rec.permission_id || this.submitted.has(rec.permission_id)) continue;
      this.submitted.add(rec.permission_id);
      this.meta.set(rec.permission_id, rec);
      try {
        await fetch(this.opts.permissionUrl, {
          method: "POST",
          headers: await this.authHeaders({ "content-type": "application/json" }),
          body: JSON.stringify({
            permission_id: rec.permission_id,
            scope: rec.scope,
            summary: rec.scope,
            host: rec.host,
            method: rec.method,
            path: rec.path
          })
        });
      } catch (err) {
        this.submitted.delete(rec.permission_id);
        console.error(`[perm] submit failed: ${err.message}`);
      }
    }
  }
  /** Poll outstanding requests; on approval, write a scoped, expiring grant for the proxy. */
  async pollGrants() {
    const now = Math.floor(Date.now() / 1e3);
    let changed = false;
    for (const pid of this.submitted) {
      const existing = this.grants[pid];
      if (existing && existing.expires_at > now) continue;
      try {
        const res = await fetch(
          `${this.opts.permissionUrl}?permission_id=${encodeURIComponent(pid)}`,
          { headers: await this.authHeaders() }
        );
        if (!res.ok) continue;
        const { status } = await res.json();
        if (status === "approved") {
          this.grants[pid] = {
            expires_at: now + this.opts.ttlSeconds,
            scope: this.meta.get(pid)?.scope ?? ""
          };
          changed = true;
        } else if (status === "denied" || status === "expired") {
          if (this.grants[pid]) {
            delete this.grants[pid];
            changed = true;
          }
        }
      } catch {
      }
    }
    if (changed) {
      writeFileSync6(this.opts.grantsPath, JSON.stringify(this.grants, null, 2), { mode: 384 });
      console.log(`[perm] wrote ${Object.keys(this.grants).length} grant(s)`);
    }
  }
};

// src/activity.ts
import { closeSync, existsSync as existsSync6, fstatSync, mkdirSync as mkdirSync5, openSync, readSync, readFileSync as readFileSync8, renameSync as renameSync3, statSync, writeFileSync as writeFileSync7 } from "fs";
import { dirname as dirname3, join as join2 } from "path";
var MAX_CHUNK = 4 * 1024 * 1024;
var ActivityShipper = class {
  constructor(opts) {
    this.opts = opts;
    this.batchSize = opts.batchSize ?? 200;
    this.fetchImpl = opts.fetchImpl ?? fetch;
    this.cursor = this.loadCursor();
  }
  cursor = { inode: 0, offset: 0 };
  backoffMs = 0;
  nextAttemptAt = 0;
  batchSize;
  fetchImpl;
  loadCursor() {
    try {
      const c = JSON.parse(readFileSync8(this.opts.cursorPath, "utf8"));
      if (typeof c.inode === "number" && typeof c.offset === "number") return c;
    } catch {
    }
    return { inode: 0, offset: 0 };
  }
  saveCursor() {
    mkdirSync5(dirname3(this.opts.cursorPath), { recursive: true });
    const tmp = join2(dirname3(this.opts.cursorPath), ".activity.cursor.tmp");
    writeFileSync7(tmp, JSON.stringify(this.cursor), { mode: 384 });
    renameSync3(tmp, this.opts.cursorPath);
  }
  /** One pass: ship everything unshipped, one batch at a time, until caught up or an error. */
  inFlight = false;
  async tick() {
    const total = { read: 0, accepted: 0, duplicates: 0, skipped: 0 };
    if (this.inFlight) return total;
    if (Date.now() < this.nextAttemptAt) return total;
    if (!existsSync6(this.opts.logPath)) return total;
    this.inFlight = true;
    try {
      return await this.tickInner(total);
    } finally {
      this.inFlight = false;
    }
  }
  async tickInner(total) {
    const live = statSync(this.opts.logPath);
    const liveInode = Number(live.ino);
    if (this.cursor.inode && this.cursor.inode !== liveInode) {
      const rotated = this.opts.logPath + ".1";
      if (existsSync6(rotated) && Number(statSync(rotated).ino) === this.cursor.inode) {
        const done = await this.shipFrom(rotated, total);
        if (!done) return total;
      }
      this.cursor = { inode: liveInode, offset: 0 };
      this.saveCursor();
    } else if (!this.cursor.inode) {
      this.cursor = { inode: liveInode, offset: 0 };
    } else if (live.size < this.cursor.offset) {
      this.cursor.offset = 0;
    }
    await this.shipFrom(this.opts.logPath, total);
    return total;
  }
  /**
   * Ship complete lines from `this.cursor.offset` in `path` in batches. Returns true when the
   * file is fully shipped, false when a batch was refused (cursor left on the unshipped part).
   */
  async shipFrom(path, total) {
    for (; ; ) {
      const { records, consumed, skipped } = this.readBatch(path);
      total.skipped += skipped;
      if (records.length === 0) {
        if (consumed > 0) {
          this.cursor.offset += consumed;
          this.saveCursor();
          continue;
        }
        return true;
      }
      const ok = await this.post(records);
      if (!ok) return false;
      total.read += records.length;
      total.accepted += ok.accepted;
      total.duplicates += ok.duplicates;
      this.cursor.offset += consumed;
      this.saveCursor();
      if (records.length < this.batchSize) return true;
    }
  }
  readBatch(path) {
    const fd = openSync(path, "r");
    try {
      const size = fstatSync(fd).size;
      const want = Math.min(MAX_CHUNK, Math.max(0, size - this.cursor.offset));
      if (want === 0) return { records: [], consumed: 0, skipped: 0 };
      const buf = Buffer.alloc(want);
      const n = readSync(fd, buf, 0, want, this.cursor.offset);
      const text = buf.subarray(0, n).toString("utf8");
      const records = [];
      let consumed = 0;
      let skipped = 0;
      let from = 0;
      while (records.length < this.batchSize) {
        const nl = text.indexOf("\n", from);
        if (nl === -1) break;
        const line = text.slice(from, nl);
        from = nl + 1;
        consumed = Buffer.byteLength(text.slice(0, from), "utf8");
        if (!line.trim()) continue;
        try {
          records.push(JSON.parse(line));
        } catch {
          skipped += 1;
        }
      }
      return { records, consumed, skipped };
    } finally {
      closeSync(fd);
    }
  }
  async post(records) {
    try {
      const res = await this.fetchImpl(this.opts.activityUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${await this.opts.getToken()}`, "content-type": "application/json" },
        body: JSON.stringify({ records })
      });
      if (res.status === 400 || res.status === 413) {
        console.error(`[activity] batch rejected (HTTP ${res.status}); dropping ${records.length} records`);
        this.backoffMs = 0;
        return { accepted: 0, duplicates: 0 };
      }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      this.backoffMs = 0;
      return { accepted: body.accepted ?? 0, duplicates: body.duplicates ?? 0 };
    } catch (err) {
      this.backoffMs = Math.min(this.backoffMs ? this.backoffMs * 2 : 5e3, 6e4);
      this.nextAttemptAt = Date.now() + this.backoffMs;
      console.error(`[activity] ship failed (${err.message}); retry in ${this.backoffMs / 1e3}s`);
      return null;
    }
  }
};

// src/auth.ts
var saasPublicKey = null;
function setSaasPublicKey(key) {
  saasPublicKey = key;
}
async function verifyRequest(req) {
  if (!saasPublicKey) return null;
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  try {
    const key = await importSPKI(saasPublicKey, "EdDSA");
    const { payload } = await jwtVerify(token, key, { algorithms: ["EdDSA"] });
    return payload;
  } catch {
    return null;
  }
}
async function requireAuth(req, res) {
  const payload = await verifyRequest(req);
  if (!payload) {
    res.writeHead(401, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Unauthorized" }));
    return false;
  }
  return true;
}

// src/ready.ts
import { readFileSync as readFileSync9 } from "fs";
var KEYS_DIR = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
function readKeyFile(name) {
  try {
    return readFileSync9(`${KEYS_DIR}/${name}`, "utf-8").trim();
  } catch {
    return null;
  }
}
async function signReadyToken(vmId, privateKeyPem) {
  const key = await importPKCS8(privateKeyPem, "EdDSA");
  return new SignJWT({ vmId }).setProtectedHeader({ alg: "EdDSA" }).setIssuedAt().setExpirationTime("30s").sign(key);
}
var sleep2 = (ms) => new Promise((r) => setTimeout(r, ms));
async function reportReady() {
  const vmId = readKeyFile("vm_id");
  const readyUrl = readKeyFile("ready_api_url");
  const privateKey = readKeyFile("vm_private_key.pem");
  if (!vmId || !readyUrl || !privateKey) {
    console.warn("[ready] missing vm_id / ready_api_url / vm_private_key.pem \u2014 skipping");
    return;
  }
  const maxAttempts = 20;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const token = await signReadyToken(vmId, privateKey);
      const res = await fetch(readyUrl, { method: "POST", headers: { Authorization: `Bearer ${token}` } });
      if (res.ok) {
        console.log(`[ready] reported ready (attempt ${attempt})`);
        return;
      }
      console.warn(`[ready] attempt ${attempt}/${maxAttempts}: HTTP ${res.status}`);
    } catch (err) {
      console.warn(`[ready] attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
    }
    await sleep2(Math.min(2e3 * attempt, 15e3));
  }
  console.error(`[ready] gave up after ${maxAttempts} attempts`);
}

// src/index.ts
var PORT = parseInt(process.env.AGENT_PORT ?? "3100", 10);
var KEYS_DIR2 = process.env.KEYS_DIR ?? "/opt/controlclaw/keys";
var BOX_KEY_PATH = process.env.BOX_KEY_PATH ?? `${KEYS_DIR2}/box_key`;
var STORE_URL = process.env.STORE_URL ?? "";
var RULES_URL = process.env.RULES_URL ?? "";
var IDENTITIES_URL = process.env.IDENTITIES_URL ?? "";
var PROXY_CONFIG_DIR = process.env.PROXY_CONFIG_DIR ?? "/run/mitm/config";
var CA_CERT_PATH = process.env.CA_CERT_PATH ?? "";
var CA_URL = process.env.CA_URL ?? "";
var PERMISSION_URL = process.env.PERMISSION_URL ?? "";
var PENDING_PATH = process.env.PENDING_PATH ?? "";
var GRANTS_PATH = process.env.GRANTS_PATH ?? `${PROXY_CONFIG_DIR}/grants.json`;
var PERMISSION_POLL_MS = parseInt(process.env.PERMISSION_POLL_MS ?? "3000", 10);
var PERMISSION_TTL = parseInt(process.env.PERMISSION_TTL ?? "300", 10);
var ACTIVITY_URL = process.env.ACTIVITY_URL ?? "";
var TRAFFIC_LOG_PATH = process.env.TRAFFIC_LOG_PATH ?? "";
var ACTIVITY_CURSOR_PATH = process.env.ACTIVITY_CURSOR_PATH ?? `${TRAFFIC_LOG_PATH}.cursor`;
var ACTIVITY_POLL_MS = parseInt(process.env.ACTIVITY_POLL_MS ?? "5000", 10);
var FIREWALL_URL = process.env.FIREWALL_URL ?? "";
var FIREWALL_POLL_MS = parseInt(process.env.FIREWALL_POLL_MS ?? "5000", 10);
var CHANNEL_STORE_PATH = process.env.CHANNEL_STORE_PATH ?? "/opt/controlclaw/state/channels.enc";
var CHANNELS_PLACEHOLDER_SWAP = process.env.CHANNELS_PLACEHOLDER_SWAP === "1";
var LLM_STORE_PATH = process.env.LLM_STORE_PATH ?? "/opt/controlclaw/state/llm.enc";
var LLM_PLAIN_KEYS = process.env.LLM_PLAIN_KEYS === "1";
var LLM_REFRESH_POLL_MS = parseInt(process.env.LLM_REFRESH_POLL_MS ?? "60000", 10);
var AGENT_VERSION = process.env.MITM_AGENT_VERSION ?? "0.1.0";
var SHIP_ONCE = process.env.SHIP_ONCE === "1";
var ORG_ID = process.env.ORG_ID ?? "";
var BOX_ID = process.env.BOX_ID ?? "";
var SYNC_ONCE = process.env.SYNC_ONCE === "1";
var SYNC_INTERVAL_MS = parseInt(process.env.SYNC_INTERVAL_MS ?? "60000", 10);
var MIGRATE_FROM_URL = process.env.MIGRATE_FROM_URL ?? "";
var MASTER_PASSWORD = process.env.MASTER_PASSWORD ?? "";
var MIGRATE_SOURCE_BOX_ID = process.env.MIGRATE_SOURCE_BOX_ID ?? "";
var ids = { orgId: ORG_ID, boxId: BOX_ID };
function die(msg) {
  console.error(`[mitm-agent] ${msg}`);
  process.exit(1);
}
var usesHttp = STORE_URL.startsWith("http") || RULES_URL.startsWith("http") || ACTIVITY_URL.startsWith("http") || FIREWALL_URL.startsWith("http");
var getToken = usesHttp ? makeBoxTokenSigner(KEYS_DIR2) : void 0;
var identities = [];
var channels = null;
var llm = null;
async function runSync(boxKey) {
  const store = makeStoreClient(STORE_URL, getToken);
  const record = await store.fetchRecord();
  const cfg = record ? decryptToConfig(record, boxKey, ids) : { credentials: [], rules: [] };
  if (RULES_URL) {
    cfg.rules = await fetchRules(RULES_URL, getToken);
  }
  if (IDENTITIES_URL) {
    cfg.identities = await fetchIdentities(IDENTITIES_URL, getToken);
    identities = cfg.identities;
  }
  if (channels) {
    cfg.credentials = [...cfg.credentials ?? [], ...channels.credentials()];
  }
  if (llm) {
    cfg.credentials = [...cfg.credentials ?? [], ...llm.credentials()];
  }
  writeProxyConfig(PROXY_CONFIG_DIR, cfg);
  console.log(
    `[mitm-agent] synced v${record?.version ?? 0}: ${(cfg.credentials ?? []).length} creds, ${(cfg.rules ?? []).length} rules, ${(cfg.identities ?? []).length} identities`
  );
}
async function maybeMigrate() {
  if (!MIGRATE_FROM_URL || !MASTER_PASSWORD) return loadOrCreateBoxKey(BOX_KEY_PATH);
  console.log("[mitm-agent] migration requested \u2014 deriving from master password");
  const source = await makeStoreClient(MIGRATE_FROM_URL).fetchRecord();
  if (!source) die("migration source record not found");
  const { record, boxKey } = await migrateToNewBox({
    source,
    masterPassword: MASTER_PASSWORD,
    sourceIds: { orgId: ORG_ID, boxId: MIGRATE_SOURCE_BOX_ID },
    newBoxId: BOX_ID
  });
  writeFileSync8(BOX_KEY_PATH, boxKey, { mode: 384 });
  await makeStoreClient(STORE_URL).putRecord(record);
  console.log(`[mitm-agent] migrated to v${record.version} under a fresh box key`);
  return boxKey;
}
function makeShipper() {
  if (!ACTIVITY_URL || !TRAFFIC_LOG_PATH || !getToken) return null;
  return new ActivityShipper({
    logPath: TRAFFIC_LOG_PATH,
    cursorPath: ACTIVITY_CURSOR_PATH,
    activityUrl: ACTIVITY_URL,
    getToken
  });
}
async function main() {
  if (!ORG_ID || !BOX_ID) die("ORG_ID and BOX_ID are required");
  if (SHIP_ONCE) {
    const shipper = makeShipper();
    if (!shipper) die("SHIP_ONCE needs ACTIVITY_URL and TRAFFIC_LOG_PATH");
    const r = await shipper.tick();
    console.log(`[activity] shipped read=${r.read} accepted=${r.accepted} duplicates=${r.duplicates} skipped=${r.skipped}`);
    process.exit(0);
  }
  if (!STORE_URL) die("STORE_URL is required");
  ensureVmKeypair(KEYS_DIR2);
  await registerPublicKey(KEYS_DIR2);
  let boxKey;
  try {
    boxKey = await maybeMigrate();
  } catch (err) {
    die(`migration failed: ${err.message}`);
  }
  if (FIREWALL_URL && getToken) {
    try {
      channels = new ChannelsFirewall({
        storePath: CHANNEL_STORE_PATH,
        boxKey,
        ids,
        agent: makeAgentClient({ sign: makeAgentTokenSigner(KEYS_DIR2, BOX_ID) }),
        identities: () => identities,
        placeholderSwap: CHANNELS_PLACEHOLDER_SWAP,
        onCredentialsChanged: () => runSync(boxKey)
      });
      console.log(`[mitm-agent] channel store loaded (${channels.summary().length} channel(s), placeholder swap ${CHANNELS_PLACEHOLDER_SWAP ? "on" : "off"})`);
    } catch (err) {
      console.error(`[mitm-agent] channel store unreadable, channel commands disabled: ${err.message}`);
    }
    try {
      llm = new LlmFirewall({
        storePath: LLM_STORE_PATH,
        boxKey,
        ids,
        agent: makeAgentClient({ sign: makeAgentTokenSigner(KEYS_DIR2, BOX_ID) }),
        codeRoutes: () => channels?.codeRoutes() ?? [],
        plainKeys: LLM_PLAIN_KEYS,
        onCredentialsChanged: () => runSync(boxKey)
      });
      const s = llm.summary();
      console.log(`[mitm-agent] llm store loaded (${s.credentials.length} credential(s), ${s.agents} agent(s), keys ${LLM_PLAIN_KEYS ? "plain" : "at the proxy"})`);
    } catch (err) {
      console.error(`[mitm-agent] llm store unreadable, llm commands disabled: ${err.message}`);
    }
  }
  try {
    await runSync(boxKey);
  } catch (err) {
    if (SYNC_ONCE) die(`sync failed: ${err.message}`);
    console.error(`[mitm-agent] sync failed (keeping previous config): ${err.message}`);
  }
  if (SYNC_ONCE) {
    console.log("[mitm-agent] sync-once complete");
    process.exit(0);
  }
  try {
    setSaasPublicKey(readFileSync10(`${KEYS_DIR2}/saas_public_key.pem`, "utf-8"));
  } catch (err) {
    die(`failed to load SaaS public key: ${err.message}`);
  }
  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);
    if (!await requireAuth(req, res)) return;
    if (url.pathname === "/health" && req.method === "GET") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", role: "mitm", org: ORG_ID, box: BOX_ID }));
      return;
    }
    if (url.pathname === "/sync" && req.method === "POST") {
      try {
        await runSync(boxKey);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      } catch (err) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: err.message }));
      }
      return;
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  });
  server.listen(PORT, "0.0.0.0", () => {
    console.log(`[mitm-agent] listening on ${PORT} (org=${ORG_ID} box=${BOX_ID})`);
    setInterval(() => void runSync(boxKey).catch((e) => console.error("[mitm-agent] resync:", e.message)), SYNC_INTERVAL_MS);
    if (CA_CERT_PATH && CA_URL && getToken) {
      void (async () => {
        try {
          const caCert = readFileSync10(CA_CERT_PATH, "utf8");
          const caSig = signDetached(KEYS_DIR2, caCert);
          const res = await fetch(CA_URL, {
            method: "POST",
            headers: { Authorization: `Bearer ${await getToken()}`, "content-type": "application/json" },
            body: JSON.stringify({ ca_cert: caCert, ca_sig: caSig })
          });
          console.log(`[mitm-agent] published signed CA cert (HTTP ${res.status})`);
        } catch (err) {
          console.error("[mitm-agent] CA publish failed:", err.message);
        }
      })();
    }
    if (PERMISSION_URL && PENDING_PATH && getToken) {
      const bridge = new PermissionBridge({
        pendingPath: PENDING_PATH,
        grantsPath: GRANTS_PATH,
        permissionUrl: PERMISSION_URL,
        getToken,
        ttlSeconds: PERMISSION_TTL
      });
      console.log("[mitm-agent] permission bridge enabled");
      setInterval(() => void bridge.tick().catch((e) => console.error("[perm] tick:", e.message)), PERMISSION_POLL_MS);
    }
    const shipper = makeShipper();
    if (shipper) {
      console.log("[mitm-agent] activity shipper enabled");
      setInterval(() => void shipper.tick().catch((e) => console.error("[activity] tick:", e.message)), ACTIVITY_POLL_MS);
    }
    if (FIREWALL_URL && getToken) {
      const control = new FirewallControl({
        firewallUrl: FIREWALL_URL,
        getToken,
        agentVersion: AGENT_VERSION,
        handlers: { ...channels?.handlers() ?? {}, ...llm?.handlers() ?? {} },
        extraResults: () => llm?.drainReports() ?? []
      });
      console.log("[mitm-agent] firewall control enabled");
      setInterval(() => void control.tick().catch((e) => console.error("[firewall] tick:", e.message)), FIREWALL_POLL_MS);
      void control.tick().catch((e) => console.error("[firewall] tick:", e.message));
    }
    if (llm) {
      const l = llm;
      setInterval(() => void l.refreshDue().catch((e) => console.error("[llm] refresh:", e.message)), LLM_REFRESH_POLL_MS);
      void l.refreshDue().catch((e) => console.error("[llm] refresh:", e.message));
    }
    void reportReady();
  });
}
void main();
/*! Bundled license information:

hash-wasm/dist/index.esm.js:
  (*!
   * hash-wasm (https://www.npmjs.com/package/hash-wasm)
   * (c) Dani Biro
   * @license MIT
   *)
*/
