"""Offline client-neutral comparison of sanitized Codex metrics.

No tool execution, API calls, session text or target details. Reports differences,
not causal attribution. The rubric/outcome is user supplied, not independently verified.
"""
from __future__ import annotations

from collections import Counter
from typing import Any


def _int(data: dict, key: str) -> int | None:
    v = data.get(key)
    return v if type(v) is int and v >= 0 else None


def summarize(metrics: dict, *, outcome: str = 'unknown', cost_usd: float | None = None) -> dict:
    if outcome not in ('unknown', 'completed', 'partial', 'failed'):
        raise ValueError('Invalid outcome')
    if not isinstance(metrics, dict):
        raise ValueError('Expected metrics object')
    if cost_usd is not None and (not isinstance(cost_usd, (float, int)) or isinstance(cost_usd, bool)
                                 or not 0 <= cost_usd <= 1_000_000):
        raise ValueError('Invalid actual cost')
    usage = metrics.get('usage', {}).get('reported_cumulative', {})
    activity = metrics.get('activity', {})
    session = metrics.get('session', {})
    if not isinstance(usage, dict) or not isinstance(activity, dict) or not isinstance(session, dict):
        raise ValueError('Invalid metric sections')
    inp, cached, output = (_int(usage, n) for n in ('input_tokens', 'cached_input_tokens', 'output_tokens'))
    if inp is not None and cached is not None and cached > inp:
        raise ValueError('Cached input greater than input')
    calls = _int(activity, 'tool_calls')
    repetitions = _int(activity, 'exact_argument_repeat_calls')
    bytool = activity.get('tool_calls_by_name', {})
    if not isinstance(bytool, dict) or any(not isinstance(k, str) or type(v) is not int or v < 0 for k,v in bytool.items()):
        raise ValueError('Invalid tool call counts')
    largest = activity.get('largest_tool_outputs') or []
    if not isinstance(largest, list):
        raise ValueError('Invalid tool output list')
    byvolume = []
    for row in largest:
        if isinstance(row, dict) and isinstance(row.get('tool'), str):
            chars = _int(row, 'total_output_chars')
            if chars is not None:
                byvolume.append({'tool': row['tool'], 'output_chars': chars,
                                 'calls_with_output': _int(row,'calls_with_output')})
    byvolume.sort(key=lambda a: a['output_chars'], reverse=True)
    dur = session.get('duration_seconds')
    if type(dur) not in (int, float) or dur < 0:
        dur = None
    return {
        'provider': session.get('provider'),
        'model_names': sorted((session.get('models_seen') or {}).keys()),
        'outcome_reported': outcome, 'cost_usd_reported': round(float(cost_usd), 4) if cost_usd is not None else None,
        'duration_seconds': dur, 'input_tokens': inp,
        'cached_input_tokens': cached, 'uncached_input_tokens': inp-cached if inp is not None and cached is not None else None,
        'output_tokens': output,
        'total_tokens': _int(usage,'total_tokens'),
        'tool_calls': calls, 'compactions': _int(activity,'compactions'),
        'repeated_argument_calls': repetitions,
        'repeated_pct': round(100*repetitions/calls,2) if calls and repetitions is not None else None,
        'native_tool_calls': sum(n for t,n in bytool.items() if t in ('exec_command','view_image','write_stdin')),
        'mcp_tool_calls': sum(n for t,n in bytool.items() if t.startswith(('lab_','oliva_'))),
        'largest_text_generators': byvolume[:8],
        'tool_call_breakdown': dict(sorted(bytool.items(), key=lambda kv:-kv[1]))
    }


def compare(a: dict, b: dict, *, same_task: bool = False) -> dict:
    def delta(k: str):
        left,right=a.get(k),b.get(k)
        if type(left) not in (int,float) or type(right) not in (int,float):
            return None
        return {'baseline':left,'candidate':right,'delta':round(right-left,4),
                'pct_change':round(100*(right-left)/left,2) if left else None}
    fields = ('cost_usd_reported','duration_seconds','total_tokens','cached_input_tokens',
              'uncached_input_tokens','output_tokens','tool_calls','compactions',
              'repeated_argument_calls','native_tool_calls','mcp_tool_calls')
    metric_deltas = {key:delta(key) for key in fields}
    quality = (a.get('outcome_reported') == 'completed' and b.get('outcome_reported') == 'completed')
    return {
        'schema':'oliva-offline-comparison-v3',
        'same_task_declared':same_task,
        'baseline':a, 'candidate':b, 'deltas':metric_deltas,
        'quality_gate': {'both_reported_completed': quality,
                         'can_attribute_changes_to_harness': False},
        'interpretation': ('Tasks declared comparable; still control client, model, tools and starting state.'
                          if same_task else
                          'DIFFERENT TASKS: results are descriptive only, NOT evidence of harness savings.'),
        'safety_note': 'No autonomous actions, permission changes or tool calls are performed.'
    }
