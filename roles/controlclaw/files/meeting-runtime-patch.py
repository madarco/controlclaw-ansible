#!/usr/bin/env python3
"""Narrow compatibility patches for integrity-pinned OpenClaw/Meet 2026.11.5.

Local Meet ignored chrome.browserProfile. Route its requests to the ephemeral guest
profile without changing ordinary browser defaults. Native automatic summaries are
local heuristics; vm-agent alone sends cleaned captions to the configured model, including AI Gateway.
Filter native caption UI artifacts before they enter the transcript database.
Transcript status polls advance delayed admission prompts and turn captions on.
Meeting consults put the captions first, then the recent voice lines, then the request; a later
consult of an unchanged consult session carries only what is new (consult-delta), with one short
line in place of the instructions it already has, and no recent voice lines that the meeting lines
repeat (consult-rules).
Google's meeting links: Google now answers meet.google.com/<code> with meet.google.com/meet/<code>,
and the Meet plugin's page checks (captions, leave, voice audio) and tab lookup take both as the
same meeting.
Refuse any unreviewed upstream build. This file must be retired as upstream fixes land.
"""
import re
import hashlib
import json
from pathlib import Path
import sys
PATCHES = json.loads(r'''[{"kind": "host", "path": "dist/plugin-sdk/meeting-runtime.js", "before": "5333b4b6b2bcfa04a4a2fc1e8a8b9d622de08da478e65ee980591e0f470367e5", "after": "97eaddc9cedd53772bbb6a68e3758d3c2a41464aeeb86b6882008c08a14d82e5", "replacements": [["body: e.body,\n\t\ttimeoutMs: e.timeoutMs\n\t}, { progress: false });", "body: e.body,\n\t\tquery: { profile: \"cc-meetings\" },\n\t\ttimeoutMs: e.timeoutMs\n\t}, { progress: false });", 1], ["return async (t) => await e.gateway.request(\"browser.request\", {\n\t\tmethod: t.method,", "return async (t) => await e.gateway.request(\"browser.request\", {\n\t\tquery: { profile: \"cc-meetings\" },\n\t\tmethod: t.method,", 1], ["\t\ttoolsAllow: resolveRealtimeVoiceAgentConsultToolsAllow(e.toolPolicy),", "\t\ttimeoutMs: 15000,\n\t\ttoolsAllow: resolveRealtimeVoiceAgentConsultToolsAllow(\"safe-read-only\"),", 1], ["if (h.capabilities?.handlesInputAudioBargeIn === true && h.capabilities.supportsBargeIn === false) requireIsolatedInput();", "requireIsolatedInput(); // Never capture our own virtual microphone output.", 1], ["\tattachAudioProcessHandlers(a, \"input\");\n\tconst m = {\n\t\tonFatal", "\tattachAudioProcessHandlers(a, \"input\");\n\tconst m = {\n\t\tinputAudioIsolated: t.command === \"parec\" && t.args.includes(\"--device=cc_meeting_remote.monitor\") && n.command === \"pacat\" && n.args.includes(\"--device=openclaw_meeting_audio\"),\n\t\tonFatal", 1], ["if (e.hasConfiguredInputCommand || !t) return e.nativeTransport;", "if (e.nativeTransport.inputAudioIsolated === true || e.hasConfiguredInputCommand || !t) return e.nativeTransport;", 1], ["import { t as KeyedAsyncQueue } from \"../keyed-async-queue-CylheagG.mjs\";", "import { t as KeyedAsyncQueue } from \"../keyed-async-queue-CylheagG.mjs\";\nimport { k as tryBeginGatewayIndependentRootWorkAdmission } from \"../gateway-work-admission-C_AYjV_d.mjs\";", 1], ["return await consultRealtimeVoiceAgent({", "const admission = tryBeginGatewayIndependentRootWorkAdmission(\"meeting-read-only-consult\");\n\tif (!admission) throw new Error(\"Main agent is restarting or temporarily unavailable. Try the lookup again shortly.\");\n\ttry { return await admission.run(() => consultRealtimeVoiceAgent({", 1], ["\t\tabortSignal: e.abortSignal\n\t});\n}\n//#endregion\n//#region src/meeting-bot/node-invoke-policy.ts", "\t\tabortSignal: e.abortSignal\n\t})); } finally { admission.release(); }\n}\n//#endregion\n//#region src/meeting-bot/node-invoke-policy.ts", 1], ["async function consultMeetingAgent(e) {", "/** ControlClaw: the meeting consult's model and thinking (cc-meeting-voice config, meeting-model.md); none set is the agent's main model. */\nfunction ccMeetingConsultModel(cfg) {\n\tconst voice = cfg?.plugins?.entries?.[\"google-meet\"]?.config?.realtime?.providers?.[\"cc-meeting-voice\"] ?? {};\n\tconst ref = typeof voice.consultModel === \"string\" ? voice.consultModel.trim() : \"\";\n\tconst slash = ref.indexOf(\"/\");\n\tconst thinkLevel = [\"off\", \"minimal\", \"low\"].includes(voice.consultThinking) ? voice.consultThinking : \"low\";\n\treturn slash > 0 && slash < ref.length - 1 ? { provider: ref.slice(0, slash), model: ref.slice(slash + 1), thinkLevel } : { thinkLevel };\n}\nasync function consultMeetingAgent(e) {", 1], ["\t\tcontextMode: \"fork\",\n\t\targs: e.args,", "\t\tcontextMode: \"isolated\",\n\t\t...ccMeetingConsultModel(e.config),\n\t\targs: e.args,", 1]]}, {"kind": "host", "path": "dist/meeting-config-JSurllHg.mjs", "before": "65e51327ef180976d861a49eb9e1e23075de98990cd34cf6517bde284bb2d0a2", "after": "2d9c5df5cb28eefa5f13b20b6e89d65c68f736557916637eb829be3c64fd5b98", "replacements": [["const PIPEWIRE_SOURCE_NAME = PIPEWIRE_SINK_NAME;", "const PIPEWIRE_SOURCE_NAME = \"cc_meeting_remote.monitor\";", 1], ["\tawait ensurePulseModule(\"source\", PIPEWIRE_SOURCE_NAME, [\n\t\t\"module-remap-source\",\n\t\t`source_name=${PIPEWIRE_SOURCE_NAME}`,\n\t\t`master=${PIPEWIRE_MONITOR_NAME}`,\n\t\t\"channels=2\",\n\t\t\"master_channel_map=front-left,front-right\",\n\t\t\"channel_map=front-left,front-right\",\n\t\t\"remix=no\",\n\t\t`source_properties='device.description=\"${PIPEWIRE_MEETING_AUDIO_DEVICE_LABEL}\"'`\n\t]);\n", "\tif (!pulseListContains((await e.run([\n\t\t\"pactl\",\n\t\t\"list\",\n\t\t\"short\",\n\t\t\"sources\"\n\t], e.timeoutMs)).stdout ?? \"\", PIPEWIRE_SOURCE_NAME)) throw new Error(\"Isolated meeting participant audio source is missing. Repair PipeWire before joining.\");\n", 1]]}, {"kind": "host", "path": "dist/transcripts-bridge.runtime-bQxWjbAy.mjs", "before": "74ea2e0fafbc2309e578e6fe865a9f0180c259a1a2569aae92f2b67627c2c839", "after": "c609e5b25b7c391d6727aa2bd79dcc52d3ca473beb96371155022ec4ddd01446", "replacements": [["cfg: e.options.openclawConfig,", "cfg: {}, // ControlClaw generates cleaned, private notes through vm-agent.", 2]]}, {"kind": "plugin", "path": "dist/.setup/google-meet-platform-adapter-BgkYHkt6.mjs", "before": "9602d26fe3eb9ef7710b8f20f570e5870ab6ab480e3aa91b0dc4b59d7a65ef83", "after": "7adb2a9a1a8def9845444bd7fbdcbd384d7d9e4dcc615b11a37898855f5e5f7d", "replacements": [["if (/^(turn on captions|turn off captions|captions)$/i.test(clean)) return undefined;", "if (/^(turn (on|off) (captions|microphone|camera)|(captions|microphone|camera) (on|off)|(your )?microphone is (on|off|muted)|caption settings|change caption language|captions|mic_off|videocam_off)$/i.test(clean)) return undefined;", 1], ["  const join = !readOnly && ${JSON.stringify(params.autoJoin)}", "  let camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  if (!readOnly && camera && /turn off camera/i.test(buttonLabel(camera))) {\n    camera.click();\n    await waitForUi();\n    camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  }\n  const join = !readOnly && ${JSON.stringify(params.autoJoin)}", 1], ["    micMuted: mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined,", "    micMuted: mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined,\n    cameraOff: camera ? /turn on camera/i.test(buttonLabel(camera)) : undefined,", 1], ["  return JSON.stringify({\n    clickedJoin: Boolean(join),", "  // Admission and permission prompts can replace the controls during this probe.\n  // Re-read the current controls before reporting the Transcript mute invariant.\n  await waitForUi();\n  mic = findCallControlButton(/^\\\\s*turn (?:off|on) microphone\\\\b/i);\n  camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  if (!readOnly && !allowMicrophone && mic && /turn off microphone/i.test(buttonLabel(mic))) {\n    mic.click(); await waitForUi();\n    mic = findCallControlButton(/^\\\\s*turn (?:off|on) microphone\\\\b/i);\n  }\n  if (!readOnly && !allowMicrophone && camera && /turn off camera/i.test(buttonLabel(camera))) {\n    camera.click(); await waitForUi();\n    camera = findCallControlButton(/^\\\\s*turn (?:off|on) camera\\\\b/i);\n  }\n  return JSON.stringify({\n    clickedJoin: Boolean(join),", 1], ["if (/^(turn (on|off) (captions|microphone|camera)", "if (/^(?:(?:your )?(?:camera|microphone) is (?:on|off|muted)[.!]?\\s*)+$/i.test(clean)) return undefined;\n    if (/^(turn (on|off) (captions|microphone|camera)", 1], ["  const inCall = buttons().some((button) => /leave call/i.test(button.getAttribute('aria-label') || text(button)));", "  let inCall = buttons().some((button) => /leave call/i.test(button.getAttribute('aria-label') || text(button)));", 1], ["  const lobbyWaiting = !inCall", "  let lobbyWaiting = !inCall", 1], ["  // Admission and permission prompts can replace", "  const admissionPending = /asking to (?:be let in|join)|you.?ll join when someone lets you in|waiting to be let in|someone[^.]*let you in|you can join when/i.test(text(document.body));\n  // Meet shows Leave call in its admission lobby too; it is not proof of admission.\n  if (admissionPending) { inCall = false; lobbyWaiting = true; }\n  // Admission and permission prompts can replace", 1], ["const admissionPending = /asking to", "const admissionPending = /please wait until a meeting host brings you into the call|asking to", 1], ["  return JSON.stringify({\n    clickedJoin: Boolean(join),", "  // Transcript's dedicated browser denies device capture at the browser level.\n  // Meet labels blocked devices as \"problem\", so a missing toggle is not an unmute.\n  const devicePermissions = !allowMicrophone ? await Promise.all(['microphone', 'camera'].map(async name => {\n    try { return (await navigator.permissions.query({name})).state; } catch { return 'unknown'; }\n  })) : [];\n  return JSON.stringify({\n    clickedJoin: Boolean(join),", 1], ["    micMuted: mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined,", "    micMuted: devicePermissions[0] === 'denied' || (mic ? /turn on microphone/i.test(buttonLabel(mic)) : undefined),", 1], ["    cameraOff: camera ? /turn on camera/i.test(buttonLabel(camera)) : undefined,", "    cameraOff: devicePermissions[1] === 'denied' || (camera ? /turn on camera/i.test(buttonLabel(camera)) : undefined),", 1], ["  if (!inCall && googleLoginRequired) {", "  if (!inCall && /you can.t join this video call|you are not allowed to join/i.test(pageText)) {\n    manualAction = manualActionFor(\"meet-admission-denied\", \"Google Meet refused guest admission.\");\n  } else if (!inCall && googleLoginRequired) {", 1], ["(?:on|off|muted)[.!]?\\s*)+$/i.test(clean)", "(?:on|off|muted)[.!]?\\\\s*)+$/i.test(clean)", 1], ["    if (/^(turn (on|off) (captions|microphone|camera)", "    if (/^(?:you have joined the call\\\\.(?:\\\\s*(?:there (?:is|are) (?:one|\\\\d+) other (?:person|people) in the call|your (?:camera|microphone) is (?:off|on|muted)|your hand is (?:lowered|raised))\\\\.)*|(?:arrow_downward\\\\s*)?jump to bottom)$/i.test(clean)) return undefined;\n    if (/^(turn (on|off) (captions|microphone|camera)", 1], ["  const admissionPending = /please wait until a meeting host brings you into the call|asking to (?:be let in|join)|you.?ll join when someone lets you in|waiting to be let in|someone[^.]*let you in|you can join when/i.test(text(document.body));\n", "", 1], ["  let inCall = buttons().some((button) => /leave call/i.test(button.getAttribute('aria-label') || text(button)));", "  let inCall = buttons().some((button) => /leave call/i.test(button.getAttribute('aria-label') || text(button)));\n  const admissionPending = /please wait until a meeting host brings you into the call|asking to (?:be let in|join)|you.?ll join when someone lets you in|waiting to be let in|someone[^.]*let you in|you can join when/i.test(text(document.body));\n  if (admissionPending) inCall = false; // Do not start caption capture in the lobby.", 1], ["const devicePermissions = !allowMicrophone ? await Promise.all", "const devicePermissions = await Promise.all", 1], ["  })) : [];\n  return JSON.stringify({", "  }));\n  return JSON.stringify({", 1], ["if (/\\\\bOpenClaw Meeting Audio\\\\b/i.test(label))", "if (/(?:\\\\bOpenClaw Meeting Audio\\\\b|\\\\bopenclaw_meeting_audio\\\\b)/i.test(label))", 1], ["      'select[aria-label*=\"microphone\" i]',", "      'button[aria-label^=\"Microphone:\" i]',\n      'select[aria-label*=\"microphone\" i]',", 1], ["device.kind === 'audiooutput' && isMeetingAudioDevice(device.label)", "device.kind === 'audiooutput' && /cc_meeting_remote/i.test(device.label)", 1], ["        inputFamily &&\n        audioDeviceFamily(device.label) === inputFamily", "        /cc_meeting_remote/i.test(device.label)", 1], ["permissions: [\"audioCapture\", \"videoCapture\"]", "permissions: [\"audioCapture\"]", 1], ["Granted Meet microphone/camera permissions through browser control.", "Granted Meet microphone permission through browser control.", 1], ["    const mediaElements = [...document.querySelectorAll('audio, video')]", "    // Meet also renders audio outside DOM media elements. Select its actual speaker\n    // control, keeping participant playback separate from the injected microphone.\n    const isolatedOutput = (await navigator.mediaDevices.enumerateDevices()).find(\n      device => device.kind === 'audiooutput' && /cc_meeting_remote/i.test(device.label));\n    if (isolatedOutput) {\n      let speaker = document.querySelector('button[aria-label^=\"Speaker:\" i]');\n      if (!speaker && !readOnly) { await openMicrophoneDeviceSettings(); speaker = document.querySelector('button[aria-label^=\"Speaker:\" i]'); }\n      if (speaker && !/cc_meeting_remote/i.test(deviceNodeLabel(speaker)) && !readOnly) {\n        speaker.click(); await waitForUi();\n        const choice = [...document.querySelectorAll('[role=\"menuitemradio\"]')].find(node => /cc_meeting_remote/i.test(deviceNodeLabel(node)));\n        choice?.click(); await waitForUi();\n        speaker = document.querySelector('button[aria-label^=\"Speaker:\" i]');\n      }\n      if (speaker && /cc_meeting_remote/i.test(deviceNodeLabel(speaker))) {\n        audioOutputRouted = true; audioOutputDeviceLabel = isolatedOutput.label;\n        return;\n      }\n    }\n    const mediaElements = [...document.querySelectorAll('audio, video')]", 1], ["currentUrl.pathname.toLowerCase().replace(/\\\\/$/, \"\");", "currentUrl.pathname.toLowerCase().replace(/\\\\/$/, \"\").replace(/^\\\\/meet(?=\\\\/[a-z]{3}-[a-z]{4}-[a-z]{3}$)/, \"\");", 2], ["currentUrl.origin + currentUrl.pathname.toLowerCase().replace(/[/]$/, \"\") === expectedUrl", "currentUrl.origin + currentUrl.pathname.toLowerCase().replace(/[/]$/, \"\").replace(/^[/]meet(?=[/][a-z]{3}-[a-z]{4}-[a-z]{3}$)/, \"\") === expectedUrl", 1], ["        audioOutputRouted = Boolean(control) && audioDeviceFamily(deviceNodeLabel(control)) === audioDeviceFamily(output.label);", "        audioOutputRouted = Boolean(control) && /cc_meeting_remote/i.test(output.label) && /cc_meeting_remote/i.test(deviceNodeLabel(control));", 1]]}, {"kind": "plugin", "path": "dist/.setup/chrome-create-CNx6SmjM.mjs", "before": "b61ae3ed12556e3170a4634e4e37a1bea8a6cda2cfec98cc88ebbdce048c0545", "after": "638c7f06fceaaac8027f353c09e231996c09021870e12adfe64a929c1d7b7ac4", "replacements": [["const match = parsed.pathname.match(/^\\/([a-z]{3}-[a-z]{4}-[a-z]{3})(?:\\/)?$/i);", "const match = parsed.pathname.match(/^\\/(?:meet\\/)?([a-z]{3}-[a-z]{4}-[a-z]{3})(?:\\/)?$/i);", 1]]}, {"kind": "plugin", "path": "dist/.setup/runtime-IdGopIGm.mjs", "before": "dc99a64a963bce6cfd6c8a5b8ac5a882bd9119acdc3e092348bb885706791f8a", "after": "18f180fad553143fa4b8de79cceb6e642158cfcd872204cab86349b6ed14c1b4", "replacements": [["\t\t\treadOnly: true\n\t\t});", "\t\t\treadOnly: session.mode !== \"transcribe\"\n\t\t});", 1], ["const result = await recoverCurrentMeetTab({\n\t\t\t\truntime: this.params.runtime,", "const result = await recoverCurrentMeetTab({\n\t\t\t\tmeetingSessionId: session.id,\n\t\t\t\truntime: this.params.runtime,", 1], ["\t\t\tlocationLabel: route.transport === \"chrome-node\" ? \"on the selected Chrome node\" : \"in local Chrome\",\n\t\t\tmode: params.mode ?? \"bidi\",", "\t\t\tlocationLabel: route.transport === \"chrome-node\" ? \"on the selected Chrome node\" : \"in local Chrome\",\n\t\t\tmeetingSessionId: params.meetingSessionId,\n\t\t\tmode: params.mode ?? \"bidi\",", 1], ["readOnly: session.mode !== \"transcribe\"", "readOnly: false", 1]]}, {"kind": "host", "path": "dist/agent-consult-tool-DTRzLYLc.mjs", "before": "e7526b2da37f777f08609fd8e392b092e6ac58a45d0f4303cd1196ff47b7597d", "after": "56cb8f04ae7b60abab46a94c4c1b9bf07d469420811ced683574891c39b5ea85", "replacements": [["function buildRealtimeVoiceAgentConsultPrompt(e) {\n\tconst t = parseRealtimeVoiceAgentConsultArgs(e.args);\n\tconst n = e.assistantLabel ?? \"Agent\";\n\tconst r = e.questionSourceLabel ?? e.userLabel.toLowerCase();\n\tconst i = e.transcript.slice(-12).map((t) => `${t.role === \"assistant\" ? n : e.userLabel}: ${t.text}`).join(\"\\n\");\n\treturn [\n\t\t`Live voice request from the ${r} during ${e.surface}.`,\n\t\t\"Act as the configured OpenClaw agent on behalf of this user. Use available tools when the request asks you to do work.\",\n\t\t\"When finished, return only the concise result the realtime voice agent should speak back.\",\n\t\t\"Report a security or approval block only when an actual tool result says so. Distinguish tool errors from permission denials; do not invent a blocked attempt. If a read-only call fails, correct the tool or arguments and continue when possible.\",\n\t\t\"Do not include markdown, tool logs, or private reasoning. Include citations only when the spoken answer needs them.\",\n\t\tt.responseStyle ? `Spoken style: ${t.responseStyle}` : void 0,\n\t\ti ? `Recent voice transcript for context:\\n${i}` : void 0,\n\t\tt.context ? `Additional realtime context:\\n${t.context}` : void 0,\n\t\t`User request:\\n${t.question}`\n\t].filter(Boolean).join(\"\\n\\n\");\n}\n", "function buildRealtimeVoiceAgentConsultPrompt(e) {\n\tconst t = parseRealtimeVoiceAgentConsultArgs(e.args);\n\tconst n = e.assistantLabel ?? \"Agent\";\n\tconst r = e.questionSourceLabel ?? e.userLabel.toLowerCase();\n\tconst i = e.transcript.slice(-12).map((t) => `${t.role === \"assistant\" ? n : e.userLabel}: ${t.text}`).join(\"\\n\");\n\tconst meetingContext = t.context?.startsWith(\"The meeting so far, from its captions\") === true;\n\tconst ccRulesEnd = t.context?.startsWith(\"How to handle this request (from ControlClaw\") === true ? t.context.indexOf(\"\\n\\n\") : -1;\n\tconst ccRules = ccRulesEnd > 0 ? t.context.slice(0, ccRulesEnd) : t.context?.startsWith(\"How to handle this request (from ControlClaw\") === true ? t.context : \"\";\n\t// ControlClaw (consult-rules): a later consult of the same meeting session (`ccMeetingDelta`, the\n\t// patched realtime-session-harness) has these instructions, and the rules unless they changed, in\n\t// its history already: one short line instead, and its context (time, speaker, the new part of the\n\t// meeting) as it is.\n\tconst ccDelta = e.ccMeetingDelta === true;\n\tconst ccRest = ccRulesEnd > 0 ? t.context.slice(ccRulesEnd + 2) : ccDelta && !ccRules ? t.context ?? \"\" : \"\";\n\treturn [\n\t\t...(ccDelta ? [ccRules ? \"Another live voice request from the same meeting. The instructions above still apply; the rules below replace the earlier ones.\" : \"Another live voice request from the same meeting; the instructions above still apply.\"] : [\n\t\t\t`Live voice request from the ${r} during ${e.surface}.`,\n\t\t\t\"Act as the configured OpenClaw agent on behalf of this user. Use available tools when the request asks you to do work.\",\n\t\t\t\"When finished, return only the concise result the realtime voice agent should speak back.\",\n\t\t\t\"Report a security or approval block only when an actual tool result says so. Distinguish tool errors from permission denials; do not invent a blocked attempt. If a read-only call fails, correct the tool or arguments and continue when possible.\",\n\t\t\t\"Do not include markdown, tool logs, or private reasoning. Include citations only when the spoken answer needs them.\"\n\t\t]),\n\t\tt.responseStyle ? `Spoken style: ${t.responseStyle}` : void 0,\n\t\tccRules || void 0,\n\t\tmeetingContext ? t.context : void 0,\n\t\tccRest || void 0,\n\t\ti ? `${meetingContext ? \"Recent voice transcript, the last few sentences from the realtime audio (it may overlap with the last captions)\" : \"Recent voice transcript for context\"}:\\n${i}` : void 0,\n\t\tt.context && !meetingContext && !ccRules && !ccRest ? `Additional realtime context:\\n${t.context}` : void 0,\n\t\t`User request:\\n${t.question}`\n\t].filter(Boolean).join(\"\\n\\n\");\n}\n", 1]]}, {"kind": "host", "path": "dist/realtime-session-harness-Dko5QvPt.mjs", "before": "63f9af34625546e9587c2615217332ac988b5fe1b50917bfc36ca03c8c33c9ae", "after": "34a2e67fb046f67d6122312ec84dfd187db062e27f874b3d84f41d04a0b5c900", "replacements": [["async function consultRealtimeVoiceAgent(e) {\n\te.abortSignal?.throwIfAborted();", "/** ControlClaw (consult-delta): what the last answered meeting consult of each consult session went to, in this process. */\nconst ccMeetingContextSessions = new Map();\nconst ccMeetingVoiceKey = (entry) => `${entry?.role}\\u0000${entry?.text}`;\n/**\n * ControlClaw (consult-rules): the context carries lines of the meeting (cc-meeting-voice's sections;\n * from its captions or, with captions off, from the voice log). The recent voice lines then only\n * repeat them, the agent's own lines included.\n */\nconst ccMeetingCaptions = (context) => typeof context === \"string\" && /(?:^|\\n\\n)(?:The meeting so far, from its captions|More of the meeting since your last answer, from its captions)/.test(context);\n/**\n * ControlClaw (consult-rules): the fixed parts cc-meeting-voice puts first in a meeting consult's\n * whole context: its rules, then the meeting's task list (Full agent). A later consult of a session\n * gets them only when they differ from what that session last recorded.\n */\nfunction ccMeetingFixed(context) {\n\tconst parts = typeof context === \"string\" ? context.split(\"\\n\\n\") : [];\n\treturn {\n\t\trules: parts[0]?.startsWith(\"How to handle this request (from ControlClaw\") ? parts[0] : \"\",\n\t\ttasks: parts.slice(0, 2).find((p) => p.startsWith(\"This meeting's tasks (\")) ?? \"\"\n\t};\n}\n/**\n * ControlClaw: a meeting consult carries the whole meeting (`args.context`) and, from cc-meeting-voice's\n * second answered consult on, only what is new (`args.ccMeetingDelta`). The new part is used only when\n * this consult session is the one the last answered consult went to and has not been reset or\n * compacted since; anything else (a new meeting, a restart of this process, a reset or deleted\n * session, a compaction) gets the whole meeting. The recent voice lines then leave out those that\n * consult already carried.\n */\nfunction ccMeetingContextChoice(params, sessionEntry) {\n\tconst meeting = /:subagent:google-meet:/.test(params.sessionKey ?? \"\");\n\tconst args = params.args && typeof params.args === \"object\" ? params.args : null;\n\tconst delta = meeting && typeof args?.ccMeetingDelta === \"string\" ? args.ccMeetingDelta : null;\n\tconst mark = { sessionId: sessionEntry?.sessionId, compactionCount: sessionEntry?.compactionCount ?? 0 };\n\tconst last = meeting ? ccMeetingContextSessions.get(params.sessionKey) : void 0;\n\t// A history-turn limit drops early turns without a compaction. It is read from channels.<provider>,\n\t// and for this key the provider is \"subagent\", which is not a channel; should one ever set a limit\n\t// there, the delta is not used.\n\tconst limited = Object.entries(params.cfg?.channels ?? {}).some(([name, c]) => name.toLowerCase() === \"subagent\" && c && typeof c === \"object\" && (c.historyLimit != null || c.dmHistoryLimit != null || c.dms != null || c.accounts != null));\n\tconst used = !!delta && !!last && !limited && !!mark.sessionId && last.sessionId === mark.sessionId && last.compactionCount === mark.compactionCount;\n\tconst { ccMeetingDelta: _ccDelta, ...rest } = args ?? {};\n\tconst transcript = Array.isArray(params.transcript) ? params.transcript : [];\n\t// The rules and the task list go first in a later consult only when this session last recorded\n\t// others: a setting turned on or off, a task started or ended.\n\tconst fixed = ccMeetingFixed(args?.context);\n\tconst context = used ? [fixed.rules !== last.rules ? fixed.rules : \"\", fixed.tasks !== last.tasks ? fixed.tasks : \"\", delta].filter(Boolean).join(\"\\n\\n\") : null;\n\treturn {\n\t\tmeeting,\n\t\tused,\n\t\tmark,\n\t\tfixed,\n\t\targs: args ? used ? { ...rest, context } : rest : params.args,\n\t\ttranscript: meeting && ccMeetingCaptions(used ? delta : args?.context) ? [] : used ? ccMeetingVoiceFresh(transcript, last.voice) : params.transcript,\n\t\tvoice: transcript.map(ccMeetingVoiceKey)\n\t};\n}\n/**\n * ControlClaw: the voice lines after those an earlier consult carried. The lines are a window that\n * moves on, so the new list starts somewhere inside the old one: the longest end of the old list that\n * the new one starts with is what was carried. With no overlap, all of them are new.\n */\nfunction ccMeetingVoiceFresh(transcript, carried) {\n\tconst keys = transcript.map(ccMeetingVoiceKey);\n\tfor (let k = Math.min(carried.length, keys.length); k > 0; k--) {\n\t\tlet same = true;\n\t\tfor (let i = 0; i < k && same; i++) same = keys[i] === carried[carried.length - k + i];\n\t\tif (same) return transcript.slice(k);\n\t}\n\treturn transcript;\n}\n/**\n * ControlClaw: after an answered meeting consult, what its session is now; forgotten when it changed\n * during the run. True when it was recorded: cc-meeting-voice counts the lines it sent as delivered\n * only then (`ccRecorded` on the result).\n */\nfunction ccMeetingContextRecord(params, agentId, storePath, choice) {\n\tif (!choice.meeting) return false;\n\tlet recorded = false;\n\ttry {\n\t\tconst after = params.agentRuntime.session.getSessionEntry({ agentId, storePath, sessionKey: params.sessionKey, readConsistency: \"latest\" });\n\t\tif (after && after.sessionId === choice.mark.sessionId && (after.compactionCount ?? 0) === choice.mark.compactionCount) {\n\t\t\tccMeetingContextSessions.delete(params.sessionKey);\n\t\t\tccMeetingContextSessions.set(params.sessionKey, { ...choice.mark, voice: choice.voice, rules: choice.fixed.rules, tasks: choice.fixed.tasks });\n\t\t\tif (ccMeetingContextSessions.size > 200) ccMeetingContextSessions.delete(ccMeetingContextSessions.keys().next().value);\n\t\t\trecorded = true;\n\t\t} else ccMeetingContextSessions.delete(params.sessionKey);\n\t} catch {\n\t\tccMeetingContextSessions.delete(params.sessionKey);\n\t}\n\tparams.logger?.info?.(`[talk] meeting consult context: ${choice.used ? \"since the last answer\" : \"the whole meeting\"}${recorded ? \"\" : \" (not recorded)\"}`);\n\treturn recorded;\n}\nasync function consultRealtimeVoiceAgent(e) {\n\te.abortSignal?.throwIfAborted();", 1], ["\t\t\tconst m = t.sessionId;\n\t\t\tawait assertConsultModelSelectionUnlocked(u);", "\t\t\tconst m = t.sessionId;\n\t\t\tconst ccMeetingContext = ccMeetingContextChoice(e, t);\n\t\t\tawait assertConsultModelSelectionUnlocked(u);", 1], ["\t\t\t\t\tprompt: buildRealtimeVoiceAgentConsultPrompt(e),", "\t\t\t\t\tprompt: buildRealtimeVoiceAgentConsultPrompt({\n\t\t\t\t\t\t...e,\n\t\t\t\t\t\targs: ccMeetingContext.args,\n\t\t\t\t\t\ttranscript: ccMeetingContext.transcript,\n\t\t\t\t\t\tccMeetingDelta: ccMeetingContext.used\n\t\t\t\t\t}),", 1], ["\t\t\tassertRealtimeVoiceConsultNotInterrupted(v, b.meta);\n\t\t\tif (b.meta?.yielded === true) return {", "\t\t\tassertRealtimeVoiceConsultNotInterrupted(v, b.meta);\n\t\t\tconst ccRecorded = ccMeetingContextRecord(e, r, i, ccMeetingContext) ? { ccRecorded: true } : {};\n\t\t\tif (b.meta?.yielded === true) return {", 1], ["\t\t\t\tyielded: true\n\t\t\t};", "\t\t\t\tyielded: true,\n\t\t\t\t...ccRecorded\n\t\t\t};", 1], ["\t\t\t\treturn { text: e.fallbackText ?? \"I need a moment to verify that before answering.\" };", "\t\t\t\treturn {\n\t\t\t\t\ttext: e.fallbackText ?? \"I need a moment to verify that before answering.\",\n\t\t\t\t\t...ccRecorded\n\t\t\t\t};", 1], ["\t\t\treturn { text: S };\n\t\t});", "\t\t\treturn {\n\t\t\t\ttext: S,\n\t\t\t\t...ccRecorded\n\t\t\t};\n\t\t});", 1]]}]''')

# Host files: accept bundler hash/import-order changes only. All runtime code and imported symbols
# remain covered by the reviewed digest. Plugin archives keep their exact pins.
def host_digest(source):
    source = re.sub(r"-[A-Za-z0-9_-]{8}(?=\.mjs[\"'])", '-BUILDHASH', source)
    lines = source.splitlines(keepends=True)
    canonical = ''.join(sorted(l for l in lines if l.startswith('import ')) + [l for l in lines if not l.startswith('import ')])
    return hashlib.sha256(canonical.encode()).hexdigest()

def host_imports(text, host):
    def resolve(match):
        prefix = match.group(1)
        files = list((Path(host) / 'dist').glob(prefix + '-????????.mjs'))
        if len(files) != 1:
            raise RuntimeError('Ambiguous runtime module: ' + prefix)
        if prefix == 'gateway-work-admission' and not re.search(r'\btryBeginGatewayIndependentRootWorkAdmission as k\b', files[0].read_text()):
            raise RuntimeError('Unexpected gateway admission export')
        return '../' + files[0].name
    return re.sub(r'\.\./([a-z-]+)-[A-Za-z0-9_-]{8}\.mjs', resolve, text)

HOST_DIGESTS = {'dist/plugin-sdk/meeting-runtime.js': ('f4f3143d6755c1edefd0bf79b440b47b43ff7d1b9f850de96a01fdfa37cc92aa', '2be783385ad5972d4ccecd1bcb8fbba2d07afa7bda4390288d3c2c8895e47c86'), 'dist/meeting-config-JSurllHg.mjs': ('8ee00d9ebfb5c4e4143b8dbec0cfe38164abc672da89ee25d60efc0cdcae9fad', 'd3fa397ed5e988a7b5f51a71ecb01399eebc5a0154bf4cd72a7f660636b9ccb5'), 'dist/transcripts-bridge.runtime-bQxWjbAy.mjs': ('48a8c4092e62bcddf605edeaca68c66d5cfee55d7295ba24d5253ad3792f62ab', 'f11499412a2d808ea5b772095da195155c6cf4bedcddccbd9b90acea0274c773'), 'dist/agent-consult-tool-DTRzLYLc.mjs': ('f84c392009970acf212aeebf9035921e58971a5633291900fa0858b631eee7d7', '87d2b20fb02c3d21b1fc586b07c6a9f67efb02a87aac93fbcee71103ea4a0aef'), 'dist/realtime-session-harness-Dko5QvPt.mjs': ('24015852b4877a4b5b6f40ba76ccb16db845e483b44a61995c0ac0e2d3a4d684', '2dec37ceefc719cc809645f35c5ff5973d26f0afc09b8dfde0a61272e10b6aac')}

# Later upstream builds of a host file whose code changed only outside the replacements: their
# canonical code before the patch -> after it. The same replacements run on them, and the result must
# be exactly the "after" recorded here, so anything else is still refused. Each entry is reviewed
# against the upstream diff before it is added (controlclaw docs/ops/t-meet-9-35.md).
HOST_BUILDS = {}

def host_builds(spec_path):
    """Every reviewed (canonical before -> canonical after) pair of a host file."""
    before, after = HOST_DIGESTS[spec_path]
    return {before: after, **HOST_BUILDS.get(spec_path, {})}

# The earlier patched code of a host file (canonical digest), with how many of its replacements it
# has: only the ones after those run on it (an agent on another build of the pinned month, patched by an earlier
# release).
HOST_UPGRADES = {}

def patch(host, plugin, write=True):
    """Patch every file, or with plugin None and write False, only try the host's (--try-host)."""
    changes = []
    for spec in PATCHES:
        if plugin is None and spec['kind'] != 'host':
            continue
        path = Path(host if spec['kind'] == 'host' else plugin) / spec['path']
        if spec['kind'] == 'host' and not path.exists():
            pattern = re.sub(r'-[A-Za-z0-9_-]{8}(?=\.mjs$)', '-????????', path.name)
            matches = list(path.parent.glob(pattern))
            if len(matches) != 1:
                raise RuntimeError('Expected one reviewed runtime module: ' + str(path))
            path = matches[0]
        source = path.read_text()
        digest = hashlib.sha256(source.encode()).hexdigest()
        if digest == spec['after']:
            continue
        if spec['kind'] == 'host':
            # Host files are recognised by their canonical code, on any build of the pinned month, patched or not.
            builds = host_builds(spec['path'])
            after = HOST_DIGESTS[spec['path']][1]
            # The exact pinned build names its modules as the replacements do; another build's are looked up.
            names = (lambda text: text) if digest == spec['before'] else (lambda text: host_imports(text, host))
            canonical = host_digest(source)
            if canonical in builds.values():
                continue
            applied = HOST_UPGRADES.get(spec['path'], {}).get(canonical)
            if applied is not None:
                for old, new, count in spec['replacements'][applied:]:
                    old, new = names(old), names(new)
                    if source.count(old) != count:
                        raise RuntimeError('Unexpected runtime structure')
                    source = source.replace(old, new)
                if host_digest(source) != after:
                    raise RuntimeError('Unexpected patched runtime code')
                changes.append((path, source))
                continue
            if canonical not in builds:
                raise RuntimeError('Unexpected Meet runtime code: ' + str(path))
            after = builds[canonical]
            for old, new, count in spec['replacements']:
                old, new = names(old), names(new)
                if source.count(old) != count:
                    raise RuntimeError('Unexpected runtime structure')
                source = source.replace(old, new)
            if host_digest(source) != after:
                raise RuntimeError('Unexpected patched runtime code')
            changes.append((path, source))
            continue
        if digest not in (spec['before'], spec.get('previous')) and digest not in spec.get('upgrades', {}):
            raise RuntimeError('Unexpected Meet runtime build: ' + str(path))
        replacements = spec.get('upgrades', {}).get(digest) or (spec['upgradeReplacements'] if digest == spec.get('previous') else spec['replacements'])
        for old, new, count in replacements:
            if source.count(old) != count:
                raise RuntimeError('Unexpected runtime structure')
            source = source.replace(old, new)
        assert hashlib.sha256(source.encode()).hexdigest() == spec['after']
        changes.append((path, source))
    if not write:
        return
    # Check every file before modifying any.
    for path, source in changes:
        path.write_text(source)
    if changes:
        print('changed')

# The OpenClaw/Meet release every digest above was reviewed against. The health check shows it
# next to the installed version when a file no longer matches.
REVIEWED = '2026.11.5'

def find_plugin(root):
    """The installed Google Meet plugin under OpenClaw's state dir, or the plugin dir itself.

    Only where OpenClaw installs plugins: `extensions/google-meet`, or one npm project. OpenClaw
    2026.10 and later keep other copies under the state dir (`tmp/plugin-captures/...`), and install
    an update into a new project directory (`<project>__openclaw-generation__g-<hash>`) next to the
    previous one, whose time an update can touch after. So a copy at the reviewed version is
    preferred, then one in a generation directory, then the newest. The vm-agent passes the exact
    directory OpenClaw names (`plugins list --json`), and this is its fallback.
    """
    plugin = Path(root)
    if (plugin / 'dist/.setup').is_dir():
        return plugin
    candidates = [p.parent for p in plugin.glob('npm/projects/*/node_modules/@openclaw/google-meet/package.json')]
    candidates += [p.parent for p in plugin.glob('extensions/google-meet/package.json')]
    if not candidates:
        return None
    def version(p):
        try:
            return json.loads((p / 'package.json').read_text()).get('version')
        except (OSError, ValueError):
            return None
    def rank(p):
        project = p.parent.parent.parent
        return (version(p) == REVIEWED, '__openclaw-generation__' in project.name, project.stat().st_mtime, project.name)
    return max(candidates, key=rank)

def locate(spec, host, plugin):
    path = Path(host if spec['kind'] == 'host' else plugin) / spec['path']
    if spec['kind'] == 'host' and not path.exists():
        pattern = re.sub(r'-[A-Za-z0-9_-]{8}(?=\.mjs$)', '-????????', path.name)
        matches = list(path.parent.glob(pattern))
        return matches[0] if len(matches) == 1 else None
    return path if path.exists() else None

def check(host, plugin):
    """Read-only: is each file patched, still patchable, or an unreviewed build? Writes nothing.

    Used by the agent's health check (vm-agent patch-check.ts) as the unprivileged service user.
    Prints JSON with paths and verdicts only, never file contents.
    """
    files = []
    for spec in PATCHES:
        if spec['kind'] == 'plugin' and plugin is None:
            files.append({'path': spec['path'], 'status': 'missing'})
            continue
        path = locate(spec, host, plugin)
        if path is None:
            files.append({'path': spec['path'], 'status': 'missing'})
            continue
        source = path.read_text()
        digest = hashlib.sha256(source.encode()).hexdigest()
        if digest == spec['after']:
            status = 'patched'
        elif spec['kind'] == 'plugin' and (digest in (spec['before'], spec.get('previous')) or digest in spec.get('upgrades', {})):
            status = 'unpatched'
        elif spec['kind'] == 'host':
            builds = host_builds(spec['path'])
            canonical = host_digest(source)
            # The previous release's patch is upgraded by the next run, like an unpatched file.
            status = 'patched' if canonical in builds.values() else 'unpatched' if canonical in builds or canonical in HOST_UPGRADES.get(spec['path'], {}) else 'unknown'
        else:
            status = 'unknown'
        files.append({'path': spec['path'], 'status': status})
    return {'reviewed': REVIEWED, 'plugin': 'found' if plugin is not None else 'missing', 'files': files}

# What meeting-install-check.mjs imports from the installed OpenClaw after npm: one module per prefix
# in dist, whose final export list names the function. Checked the same way, without running it.
INSTALL_CHECK_EXPORTS = (
    ('installed-plugin-index-record-reader', 'loadInstalledPluginIndexInstallRecords'),
    ('official-external-install-records', 'isTrustedOfficialPluginInstallRecord'),
)

def install_check_exports(host):
    for prefix, name in INSTALL_CHECK_EXPORTS:
        files = [f for f in (Path(host) / 'dist').glob(prefix + '-*.mjs') if re.fullmatch(re.escape(prefix) + r'-[A-Za-z0-9_-]+\.mjs', f.name)]
        if len(files) != 1:
            raise RuntimeError('Expected one runtime module: ' + prefix)
        exports = re.search(r'export \{([^}]+)\};?\s*$', files[0].read_text())
        names = [part.strip().split(' as ')[0].strip() for part in exports.group(1).split(',')] if exports else []
        if name not in names:
            raise RuntimeError('Missing runtime export: ' + name)

if __name__ == '__main__':
    if sys.argv[1] == '--check':
        print(json.dumps(check(sys.argv[2], find_plugin(sys.argv[3]))))
        sys.exit(0)
    # An OpenClaw build not installed yet (cc-openclaw-patch, before it installs one): run every
    # host replacement on it, in memory, and write nothing. Exit 0 when the patch would apply, 1 with
    # the reason when it would refuse, so a build this file does not know is never installed.
    # The folders --try-host reads, so cc-openclaw-patch unpacks those and nothing else: each host
    # file's own, and dist, where host_imports looks modules up by name.
    if sys.argv[1] == '--host-dirs':
        print(json.dumps(sorted({str(Path(spec['path']).parent) for spec in PATCHES if spec['kind'] == 'host'} | {'dist'})))
        sys.exit(0)
    # A refusal is a JSON line with ok false. Anything else that goes wrong here is a traceback, which
    # cc-openclaw-patch does not take for a refusal.
    if sys.argv[1] == '--try-host':
        try:
            patch(sys.argv[2], None, write=False)
            install_check_exports(sys.argv[2])
        except (RuntimeError, AssertionError, FileNotFoundError) as error:
            print(json.dumps({'ok': False, 'reason': str(error) or type(error).__name__}))
            sys.exit(1)
        print(json.dumps({'ok': True}))
        sys.exit(0)
    plugin = find_plugin(sys.argv[2])
    if plugin is None:
        raise RuntimeError('Expected exactly one installed Google Meet package')
    patch(sys.argv[1], plugin)
