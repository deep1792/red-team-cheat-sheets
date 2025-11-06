#!/usr/bin/env python3
import argparse, os
from .runner import Runner, SUITES
from .reporter_html import generate_html
from .adapters.mock_adapter import MockAdapter
def main():
    parser = argparse.ArgumentParser(description='llmscan_pro - defensive LLM pentest runner')
    parser.add_argument('--target', default='mock', choices=['mock','openai'])
    parser.add_argument('--model', default='gpt-4o-mini')
    parser.add_argument('--suite', choices=list(SUITES.keys()), default='owasp2025')
    parser.add_argument('--sample-size', type=int, default=2)
    parser.add_argument('--out', default='results_run')
    parser.add_argument('--report', default='results_run/report.html')
    parser.add_argument('--budget', type=float, default=None)
    parser.add_argument('--max-calls', type=int, default=None)
    parser.add_argument('--thresholds', default=None)
    args = parser.parse_args()
    if args.target == 'openai':
        try:
            from .adapters.openai_adapter import OpenAIAdapter
            adapter = OpenAIAdapter(model=args.model)
        except Exception as e:
            raise SystemExit('OpenAI adapter init failed: ' + str(e))
    else:
        adapter = MockAdapter()
    os.makedirs(args.out, exist_ok=True)
    runner = Runner(adapter, out_dir=args.out, sample_size=args.sample_size, thresholds_path=args.thresholds)
    runner.budget = args.budget; runner.max_calls = args.max_calls
    results = runner.run_all(suite=args.suite)
    generate_html(results, args.report)
    print('Done. Report:', args.report)
if __name__ == '__main__':
    main()
