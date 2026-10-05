import { VoiceBridge } from './voice.js';
import { LiveBridge } from './live.js';

/** The provider contract receives and emits mu-law. Both bridges use PCM24. */
const phoneBridge = (Base) => class extends Base {
  constructor(req, deps) {
    const codecs = deps.codecs;
    let bridge;
    let output = codecs.createStreamingPcmResampler(24000, 8000);
    const wrapped = {
      ...req,
      providerConfig: {...req.providerConfig, surface:'phone'},
      onAudio: (pcm, meta) => {
        const audio = codecs.pcmToMulaw(output.process(pcm));
        if (audio.length) {
          bridge.phonePlaybackUntil=Math.max(Date.now(),bridge.phonePlaybackUntil??0)+audio.length/8;
          req.onAudio(audio, meta);
        }
      },
      onClearAudio: () => {
        output = codecs.createStreamingPcmResampler(24000,8000);
        if(bridge)bridge.phonePlaybackUntil=Date.now();
        req.onClearAudio?.('barge-in');
      },
    };
    super(wrapped,deps);bridge=this;
    this.input = codecs.createStreamingPcmResampler(8000,24000);
    this.codecs = codecs;
  }
  async connect() { await super.connect(); this.triggerGreeting(); }
  triggerGreeting(instructions) { this.sendUserMessage(instructions); }
  sendAudio(muLaw) {
    if (!Buffer.isBuffer(muLaw) || muLaw.length>8000) { this.fail(); return; }
    super.sendAudio(this.input.process(this.codecs.mulawToPcm(muLaw)));
  }
  handleBargeIn() {
    // gpt-live handles being talked over itself; there is no response to truncate.
    if (this instanceof LiveBridge) return super.handleBargeIn();
    // Snapshot before clear: discarded marks cannot become played audio.
    const played=this.req.getPlaybackState?.() ?? [];
    super.handleBargeIn();
    for(const p of played.slice(-8)) {
      if(typeof p.itemId!=='string'||!Number.isFinite(p.audioEndMs))continue;
      const ms=Math.max(0,Math.floor(p.audioEndMs));
      this.send(this.gateway?{type:'conversation-item-truncate',itemId:p.itemId,contentIndex:0,audioEndMs:ms}:{type:'conversation.item.truncate',item_id:p.itemId,content_index:0,audio_end_ms:ms});
    }
  }
};
export const PhoneVoiceBridge = phoneBridge(VoiceBridge);
export const PhoneLiveBridge = phoneBridge(LiveBridge);
