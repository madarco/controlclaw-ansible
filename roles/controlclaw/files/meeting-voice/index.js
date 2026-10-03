import { createRequire } from 'node:module';
import { VoiceBridge } from './voice.js';
import { PhoneVoiceBridge } from './phone.js';
const require = createRequire('/usr/lib/node_modules/openclaw/package.json');
const WebSocket = require('ws');
const codecs = require('openclaw/plugin-sdk/realtime-voice-provider');
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
    api.registerRealtimeVoiceProvider({
      id: 'cc-phone-voice', label: 'Phone speech',
      capabilities: { transports: ['gateway-relay'], inputAudioFormats: [{encoding:'g711_ulaw',sampleRateHz:8000,channels:1}], outputAudioFormats: [{encoding:'g711_ulaw',sampleRateHz:8000,channels:1}], supportsBargeIn: true, supportsToolCalls: true, handlesInputAudioBargeIn: true },
      resolveConfig: ({rawConfig}) => ({...rawConfig,surface:'phone',interruptResponseOnInputAudio:false}),
      isConfigured: ({providerConfig:c}) => !!c?.placeholder && !!c?.model,
      createBridge: req => new PhoneVoiceBridge(req, {WebSocket,codecs}),
    });
  },
};
