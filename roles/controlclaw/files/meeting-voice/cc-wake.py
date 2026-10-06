#!/usr/bin/env python3
"""Hears the agent's wake names in meeting audio, on the agent box (controlclaw
docs/plans/gpt-live-and-wake-word.md, D5/D6).

    cc-wake --check NAME...   which names the model can hear: one JSON line
    cc-wake NAME...           16 kHz mono s16le PCM on stdin, one JSON line per event on stdout

Events: {"type": "ready"}; {"type": "partial", "name", "pos"} when an utterance seems to open
with a name (used to open the voice session early); {"type": "wake", "name", "conf", "stop", "pos"}
when the final result confirms it. `pos` is the seconds of audio heard so far.

A name counts only at the start of what someone says: after at most half a second of other speech
("hey", "sorry"), or right after a pause (Vosk sometimes joins a new sentence to the one before
it). A name in the middle of a sentence does not count. Every word of it must be heard with
confidence 0.8 or more. Partial results carry no times, so they only count a name that opens them. The names are the
recognizer's whole grammar, so everything else is heard as "[unk]".

The library is loaded with ctypes from the pinned Vosk wheel: the Python package around it
imports requests, tqdm and srt for model downloads we never do. No audio is kept, nothing is
written to disk, and this process opens no network connection. Model: vosk-model-small-en-us-0.15
(Apache 2.0).
"""
import ctypes
import json
import os
import re
import sys
import unicodedata

LIB = os.environ.get('CC_WAKE_LIB', '/opt/controlclaw/cc-wake/libvosk.so')
MODEL = os.environ.get('CC_WAKE_MODEL', '/opt/controlclaw/cc-wake/model')
RATE = 16000
CHUNK = RATE // 10 * 2  # 100 ms of s16le
MIN_CONF = 0.8
LEADING = float(os.environ.get('CC_WAKE_LEADING', '0.5'))  # seconds of speech allowed before a name
PAUSE = float(os.environ.get('CC_WAKE_PAUSE', '0.25'))     # silence before a name that starts a new sentence
STOP = 'stop'


def load():
    lib = ctypes.CDLL(LIB)
    lib.vosk_set_log_level.argtypes = [ctypes.c_int]
    lib.vosk_model_new.argtypes = [ctypes.c_char_p]
    lib.vosk_model_new.restype = ctypes.c_void_p
    lib.vosk_model_find_word.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.vosk_model_find_word.restype = ctypes.c_int
    lib.vosk_recognizer_new_grm.argtypes = [ctypes.c_void_p, ctypes.c_float, ctypes.c_char_p]
    lib.vosk_recognizer_new_grm.restype = ctypes.c_void_p
    lib.vosk_recognizer_set_words.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.vosk_recognizer_accept_waveform.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int]
    lib.vosk_recognizer_accept_waveform.restype = ctypes.c_int
    for name in ('vosk_recognizer_result', 'vosk_recognizer_partial_result', 'vosk_recognizer_final_result'):
        getattr(lib, name).argtypes = [ctypes.c_void_p]
        getattr(lib, name).restype = ctypes.c_char_p
    lib.vosk_set_log_level(-1)
    model = lib.vosk_model_new(MODEL.encode())
    if not model:
        raise SystemExit('wake model unavailable')
    return lib, model


def words(text):
    return re.findall(r'[^\W_]+', unicodedata.normalize('NFKC', text).lower())


def phrase(lib, model, name):
    """The words Vosk should listen for, or None when it does not know them. A name written as one
    word but made of two known ones ("ControlClaw") is split."""
    known = lambda w: lib.vosk_model_find_word(model, w.encode()) >= 0
    out = []
    for w in words(name):
        if known(w):
            out.append(w)
            continue
        split = next(([w[:i], w[i:]] for i in range(2, len(w) - 1) if known(w[:i]) and known(w[i:])), None)
        if not split:
            return None
        out.extend(split)
    return out or None


def opening(words, phrases):
    """The name a final result opens with: Vosk's words with their times, where a run of other
    speech is one "[unk]". Returns (name, index, length) or None."""
    tokens = [w.get('word', '') for w in words]
    for start in range(len(tokens)):
        for name, ws in phrases:
            if tokens[start:start + len(ws)] != ws:
                continue
            if start == 0:
                return name, start, len(ws)
            before = words[start - 1]
            lead = sum(w.get('end', 0) - w.get('start', 0) for w in words[:start])
            pause = words[start].get('start', 0) - before.get('end', 0)
            if pause >= PAUSE or (lead <= LEADING and all(t == '[unk]' for t in tokens[:start])):
                return name, start, len(ws)
    return None


def opens_with(text, phrases):
    """The name a partial result opens with (no times): first, or after one short unknown run."""
    tokens = text.split()
    for start in (0, 1):
        if start and tokens[:1] != ['[unk]']:
            break
        for name, ws in phrases:
            if tokens[start:start + len(ws)] == ws:
                return name
    return None


def main(argv):
    if len(argv) < 2 or len(argv) > 7:
        raise SystemExit('usage: cc-wake [--check] NAME...')
    check = argv[1] == '--check'
    names = [n[:32] for n in argv[2 if check else 1:]][:5]
    lib, model = load()
    phrases = [(n, phrase(lib, model, n)) for n in names]
    if check:
        print(json.dumps({'heard': [{'name': n, 'words': ' '.join(p)} for n, p in phrases if p],
                          'unheard': [n for n, p in phrases if not p]}), flush=True)
        return
    phrases = [(n, p) for n, p in phrases if p]
    if not phrases:
        raise SystemExit('no name can be heard')
    grammar = sorted({' '.join(p) for _, p in phrases}) + [STOP, '[unk]']
    rec = lib.vosk_recognizer_new_grm(model, float(RATE), json.dumps(grammar).encode())
    lib.vosk_recognizer_set_words(rec, 1)
    emit = lambda event: print(json.dumps(event), flush=True)
    emit({'type': 'ready'})
    partial = False
    heard = 0
    stdin = sys.stdin.buffer
    while True:
        pcm = stdin.read(CHUNK)
        if not pcm:
            break
        heard += len(pcm)
        pos = round(heard / 2 / RATE, 2)
        if lib.vosk_recognizer_accept_waveform(rec, pcm, len(pcm)):
            result = json.loads(lib.vosk_recognizer_result(rec) or b'{}').get('result', [])
            partial = False
            tokens = [w.get('word', '') for w in result]
            found = opening(result, phrases)
            if found:
                name, start, size = found
                conf = min(w.get('conf', 0) for w in result[start:start + size])
                if conf >= MIN_CONF:
                    emit({'type': 'wake', 'name': name, 'conf': round(conf, 2),
                          'stop': tokens[start + size:start + size + 1] == [STOP], 'pos': pos})
        elif not partial:
            text = json.loads(lib.vosk_recognizer_partial_result(rec) or b'{}').get('partial', '')
            found = opens_with(text, phrases)
            if found:
                partial = True
                emit({'type': 'partial', 'name': found, 'pos': pos})


if __name__ == '__main__':
    try:
        main(sys.argv)
    except (BrokenPipeError, KeyboardInterrupt):
        pass
