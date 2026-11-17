#!/usr/bin/env python3
"""roles/controlclaw/files/cc-heartbeat-tool: which agents get heartbeat_respond in tools.deny.

Run from the repo root: python3 -m unittest tests/test_cc_heartbeat_tool.py
"""
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'roles/controlclaw/files/cc-heartbeat-tool'
INCLUDED = {'baseUrl': 'https://ai-gateway.vercel.sh/v1', 'api': 'openai-completions', 'models': [{'id': 'anthropic/claude-sonnet-5'}]}


def config(primary, **extra):
    cfg = {'agents': {'defaults': {'model': {'primary': primary, 'fallbacks': []}}}}
    for key, value in extra.items():
        cfg[key] = value
    return cfg


class HeartbeatTool(unittest.TestCase):
    def run_it(self, cfg):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'openclaw.json'
            path.write_text(cfg if isinstance(cfg, str) else json.dumps(cfg))
            out = subprocess.run(['python3', str(SCRIPT), str(path)], capture_output=True, text=True, check=True).stdout
        return json.loads(out)

    def test_a_claude_agent_gets_the_deny(self):
        for primary, extra in (
            ('controlclaw/anthropic/claude-sonnet-5@controlclaw:included', {'models': {'providers': {'controlclaw': INCLUDED}}}),
            ('anthropic/claude-sonnet-5-5@anthropic:controlclaw', {}),
            ('openrouter/moonshotai/kimi-k2.6', {}),
        ):
            with self.subTest(primary=primary):
                got = self.run_it(config(primary, **extra))
                self.assertEqual((got['toolMode'], got['deny'], got['changed']), (False, ['heartbeat_respond'], True))

    def test_other_entries_stay_and_a_second_run_changes_nothing(self):
        got = self.run_it(config('anthropic/claude-opus-5', tools={'deny': ['browser'], 'web': {'search': {'provider': 'parallel-free'}}}))
        self.assertEqual(got['deny'], ['browser', 'heartbeat_respond'])
        again = self.run_it(config('anthropic/claude-opus-5', tools={'deny': ['browser', 'heartbeat_respond']}))
        self.assertEqual((again['deny'], again['changed']), (['browser', 'heartbeat_respond'], False))

    def test_a_codex_agent_keeps_the_tool_and_loses_the_entry(self):
        for primary, extra in (
            ('openai/gpt-5.6-sol@openai:controlclaw-chatgpt', {}),
            ('openai/gpt-5.6-sol@openai:controlclaw', {}),
            ('anthropic/claude-sonnet-5', {'agents': {'defaults': {'model': 'anthropic/claude-sonnet-5', 'models': {'anthropic/claude-sonnet-5': {'agentRuntime': {'id': 'codex'}}}}}}),
            ('openai/gpt-5.6-sol', {'models': {'providers': {'openai': {'agentRuntime': {'id': 'codex'}, 'api': 'openai-completions'}}}}),
        ):
            with self.subTest(primary=primary):
                cfg = config(primary, tools={'deny': ['heartbeat_respond']}, **extra)
                got = self.run_it(cfg)
                self.assertEqual((got['toolMode'], got['deny'], got['changed']), (True, None, True))
                kept = self.run_it({**cfg, 'tools': {'deny': ['exec', 'heartbeat_respond']}})
                self.assertEqual(kept['deny'], ['exec'])
                fresh = self.run_it({**cfg, 'tools': {}})
                self.assertEqual((fresh['deny'], fresh['changed']), (None, False))

    def test_openai_off_the_codex_route_is_plain_mode(self):
        for extra in (
            {'models': {'providers': {'openai': {'api': 'openai-completions'}}}},
            {'models': {'providers': {'openai': {'baseUrl': 'https://proxy.example.com/v1'}}}},
            {'models': {'providers': {'openai': {'request': {'headers': {'x': '1'}}}}}},
            {'plugins': {'entries': {'codex': {'enabled': False}}}},
            {'models': {'providers': {'openai': {'agentRuntime': {'id': 'openclaw'}}}}},
            {'agents': {'defaults': {'model': 'openai/gpt-5.6-sol', 'models': {'openai/*': {'agentRuntime': 'openclaw'}}}}},
        ):
            with self.subTest(extra=extra):
                self.assertEqual(self.run_it(config('openai/gpt-5.6-sol', **extra))['toolMode'], False)

    def test_model_scoped_runtime_wins_over_the_provider(self):
        cfg = config('openai/gpt-5.6-sol', models={'providers': {'openai': {'agentRuntime': {'id': 'openclaw'}, 'models': [{'id': 'gpt-5.6-sol', 'agentRuntime': {'id': 'codex'}}]}}})
        self.assertTrue(self.run_it(cfg)['toolMode'])

    def test_the_model_the_heartbeat_runs_on_decides(self):
        codex = 'openai/gpt-5.6-sol@openai:controlclaw-chatgpt'
        heartbeat = {'agents': {'defaults': {'model': 'anthropic/claude-opus-5', 'heartbeat': {'every': '30m', 'model': codex}}}}
        self.assertTrue(self.run_it(heartbeat)['toolMode'])
        for agents in ({'defaults': {'model': 'anthropic/claude-opus-5'}, 'list': [{'id': 'main', 'model': codex}]},
                       {'defaults': {'model': 'anthropic/claude-opus-5'}, 'entries': {'main': {'model': {'primary': codex}}}},
                       {'defaults': {'model': 'anthropic/claude-opus-5'}, 'list': [{'id': 'main', 'heartbeat': {'model': codex}}]}):
            with self.subTest(agents=agents):
                self.assertTrue(self.run_it({'agents': agents})['toolMode'])
        self.assertFalse(self.run_it({'agents': {'defaults': {'model': codex, 'heartbeat': {'model': 'anthropic/claude-haiku-4.5'}}}})['toolMode'])

    def test_provider_case_and_a_model_entry_route(self):
        self.assertFalse(self.run_it(config('OpenAI/gpt-5.6-sol', models={'providers': {'openai': {'agentRuntime': {'id': 'openclaw'}}}}))['toolMode'])
        self.assertFalse(self.run_it(config('openai/gpt-5.6-sol', models={'providers': {'openai': {'models': [{'id': 'gpt-5.6-sol', 'api': 'openai-completions'}]}}}))['toolMode'])
        self.assertFalse(self.run_it(config('openai/gpt-5.6-sol', agents={'defaults': {'model': 'openai/gpt-5.6-sol', 'models': {'OpenAI/*': {'agentRuntime': {'id': 'openclaw'}}}}}))['toolMode'])

    def test_visible_replies_decides_before_the_model(self):
        self.assertTrue(self.run_it(config('anthropic/claude-opus-5', messages={'visibleReplies': 'message_tool'}))['toolMode'])
        self.assertFalse(self.run_it(config('openai/gpt-5.6-sol@openai:controlclaw-chatgpt', messages={'visibleReplies': 'automatic'}))['toolMode'])

    def test_no_model_or_no_config_changes_nothing(self):
        for cfg in ({}, {'agents': {'defaults': {}}, 'tools': {'deny': ['heartbeat_respond']}}, '', '{"agents": ', '[]'):
            with self.subTest(cfg=str(cfg)[:30]):
                got = self.run_it(cfg)
                self.assertEqual((got['toolMode'], got['deny'], got['changed']), (None, None, False))

    def test_a_string_model_and_a_deny_that_is_not_a_list(self):
        got = self.run_it({'agents': {'defaults': {'model': 'anthropic/claude-opus-5'}}, 'tools': {'deny': 'oops'}})
        self.assertEqual((got['deny'], got['changed']), (['heartbeat_respond'], True))


if __name__ == '__main__':
    unittest.main()
