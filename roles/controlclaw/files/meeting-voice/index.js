import { createRequire } from 'node:module';
import { VoiceBridge } from './voice.js';
const WebSocket = createRequire('/usr/lib/node_modules/openclaw/package.json')('ws');
const format = { encoding: 'pcm16', sampleRateHz: 24000, channels: 1 };
export default {
  id: 'cc-meeting-voice',
  register(api) {
    api.registerRealtimeVoiceProvider({
      id: 'cc-meeting-voice', label: 'Meeting speech',
      capabilities: { transports: ['gateway-relay'], inputAudioFormats: [format], outputAudioFormats: [format], supportsBargeIn: true, supportsToolCalls: true },
      resolveConfig: ({rawConfig}) => rawConfig,
      isConfigured: ({providerConfig:c}) => !!c?.placeholder && !!c?.model,
      createBridge: req => new VoiceBridge(req, { WebSocket }),
    });
  },
};
