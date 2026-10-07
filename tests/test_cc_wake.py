"""cc-wake's name rules (roles/controlclaw/files/meeting-voice/cc-wake.py), without the model."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('cc_wake', Path(__file__).parents[1] / 'roles/controlclaw/files/meeting-voice/cc-wake.py')
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)
PHRASES = [('Jarvis', ['jarvis']), ('Maria Rossi', ['maria', 'rossi'])]


def words(*spec):
    """(word, start, end) triples as Vosk returns them."""
    return [{'word': t, 'start': s, 'end': e, 'conf': 1.0} for t, s, e in spec]


class FakeLib:
    VOCAB = {'control', 'claw', 'jarvis', 'maria', 'rossi', 'claudia'}

    def vosk_model_find_word(self, model, word):
        return 1 if word.decode() in self.VOCAB else -1


class CcWake(unittest.TestCase):
    def test_names_the_model_knows_and_one_word_names_made_of_two(self):
        lib = FakeLib()
        self.assertEqual(w.phrase(lib, None, 'ControlClaw'), ['control', 'claw'])
        self.assertEqual(w.phrase(lib, None, 'Maria  Rossi'), ['maria', 'rossi'])
        self.assertEqual(w.phrase(lib, None, 'Claudia'), ['claudia'])
        self.assertIsNone(w.phrase(lib, None, 'Zorblax'))
        self.assertIsNone(w.phrase(lib, None, 'Jarvis Zorblax'))

    def test_a_name_opens_a_request_after_a_greeting_or_a_pause(self):
        self.assertEqual(w.opening(words(('jarvis', 0.5, 0.9), ('[unk]', 0.9, 2.0)), PHRASES), ('Jarvis', 0, 1))
        self.assertEqual(w.opening(words(('[unk]', 0.5, 0.8), ('jarvis', 0.8, 1.2)), PHRASES)[0], 'Jarvis', 'hey Jarvis')
        self.assertEqual(w.opening(words(('[unk]', 0.0, 2.0), ('maria', 2.4, 2.8), ('rossi', 2.8, 3.2)), PHRASES)[0], 'Maria Rossi',
                         'a new sentence after a pause, joined to the last one')

    def test_a_name_in_the_middle_of_a_sentence_does_not_count(self):
        self.assertIsNone(w.opening(words(('[unk]', 0.5, 1.2), ('jarvis', 1.23, 1.6), ('[unk]', 1.6, 2.2)), PHRASES), 'I asked Jarvis yesterday')
        self.assertIsNone(w.opening(words(('[unk]', 0.0, 1.5), ('jarvis', 1.5, 1.9)), PHRASES))
        self.assertIsNone(w.opening(words(('[unk]', 0.0, 0.3), ('maria', 0.3, 0.6)), PHRASES), 'half a name')

    def test_partial_results_count_only_a_name_that_opens_them(self):
        self.assertEqual(w.opens_with('jarvis', PHRASES), 'Jarvis')
        self.assertEqual(w.opens_with('[unk] maria rossi', PHRASES), 'Maria Rossi')
        self.assertIsNone(w.opens_with('[unk] [unk] jarvis', PHRASES))
        self.assertIsNone(w.opens_with('stop jarvis', PHRASES))


    def test_a_confirmed_name_says_where_it_began(self):
        """The adapter replays the request from the name, however long Vosk took to confirm it."""
        import io, json, sys
        from unittest import mock
        final = json.dumps({'result': words(('[unk]', 10.0, 11.0), ('jarvis', 11.6, 12.0), ('[unk]', 12.0, 30.0))}).encode()

        class Lib(FakeLib):
            calls = 0
            def vosk_recognizer_new_grm(self, *a): return 1
            def vosk_recognizer_set_words(self, *a): pass
            def vosk_recognizer_accept_waveform(self, rec, pcm, n):
                Lib.calls += 1
                return Lib.calls == 3
            def vosk_recognizer_result(self, rec): return final
            def vosk_recognizer_partial_result(self, rec): return b'{"partial": ""}'
        out = io.StringIO()
        stdin = mock.Mock(); stdin.buffer = io.BytesIO(b'\0' * w.CHUNK * 3)
        with mock.patch.object(w, 'load', return_value=(Lib(), None)), mock.patch.object(sys, 'stdin', stdin), mock.patch('sys.stdout', out):
            w.main(['cc-wake', 'Jarvis'])
        events = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertEqual(events[0], {'type': 'ready'})
        self.assertEqual(events[1]['type'], 'wake')
        self.assertEqual(events[1]['start'], 11.6)


if __name__ == '__main__':
    unittest.main()
