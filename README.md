# Skry
**Skry** is an experimental security tool for [Sui Move](https://www.sui.io/move) smart contracts that combines static program analysis with LLM-based classification.

> ⚠️ **Tool status:** proof of concept.
> The tool works, reproduces known critical vulnerabilities, and detects subtle design issues, but requires further work to handle more complex and advanced Sui Move patterns. See [the announcement](http://nowarp.io/blog/skry) for details.

The tool focuses on access control, governance, and centralization issues. It uses structural static analysis to narrow down candidates and then applies targeted LLM classification with interprocedural and cross-module taint propagation.

The overall pipeline architecture is shown below:

![pipeline](./docs/img/pipeline.png)

See [docs/architecture.md](./docs/architecture.md) and the [blog post](http://nowarp.io/blog/skry) for more details.

## Try it out

Installation:
```bash
git clone --recursive https://github.com/nowarp/skry
pip install -r requirements.txt
````

Set environment variables according to your setup:

```bash
# `claude-cli` uses local Claude Code
# `api` uses the DeepSeek API and requires DEEPSEEK_API_KEY to be set
# `manual` prints complete prompts for copy-paste into a web interface
export SKRY_LLM_MODE=manual|api|claude-cli
```

Run the analyzer on Move source files:

```bash
python3 src/main.py <source_path> --skip-tests
```
