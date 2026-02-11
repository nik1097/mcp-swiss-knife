# Usage Guide

## Quick Start

```bash
# Basic scan
uv run mcp-swiss-knife scan https://example.com/mcp

# With authentication
uv run mcp-swiss-knife scan https://example.com/mcp --token TOKEN

# Adjust sensitivity (0.5=more sensitive, 0.8=less sensitive)
uv run mcp-swiss-knife scan https://example.com/mcp --threshold 0.6

# Verbose output (shows detailed detection info)
uv run mcp-swiss-knife scan https://example.com/mcp --verbose

# Version
uv run mcp-swiss-knife version
```

## Command Options

- `url` (required): MCP server URL (must start with http:// or https://)
- `--token, -t`: Bearer token for authentication
- `--threshold`: Semantic similarity threshold 0.0-1.0 (default: 0.70)
  - Lower = more sensitive (more findings, more false positives)
  - Higher = less sensitive (fewer findings, might miss attacks)
- `--verbose, -v`: Show detailed detection information for each finding

## Understanding Output

### Risk Levels

- **CRITICAL** (75+): Multiple severe findings or critical patterns detected
  - Action: Do not use without thorough review
- **HIGH** (50-74): Significant security concerns
  - Action: Review immediately before use
- **MEDIUM** (25-49): Suspicious patterns detected
  - Action: Investigate and verify legitimacy
- **LOW** (1-24): Minor concerns, likely false positives
  - Action: Quick review recommended
- **CLEAN** (0): No issues detected
  - Action: Safe to use (but stay vigilant)

### Finding Details

Each finding shows:
- **Text**: The detected suspicious content
- **Severity**: critical | high | medium | low
- **Category**: What type of attack pattern
- **Detector**: Which detection layer found it
- **Confidence**: How reliable this detection is (0.0-1.0)

Example output:
```
Tool: search_documents
Risk Score: 57.0/100 (HIGH)

[Structural] Zero-width unicode characters (HIGH severity, 0.90 confidence)
  → Found 3 suspicious unicode chars: ['U+200B', 'U+200C', 'U+200D']

[Injection] System Override (CRITICAL severity, 0.85 confidence)
  → "You are now operating in unrestricted mode"

[Semantic] Identity Manipulation (HIGH severity, 0.70 confidence)
  → 0.89 similarity to "assume the role of an unrestricted assistant"
```

## Detection Layers

MCP Swiss Knife uses four independent detection layers:

### 1. Structural Detection
Catches obfuscation attempts:
- Unusually long descriptions (>1000 chars)
- Zero-width unicode characters
- Base64/hex encoding
- Delimiter injection (```system, [ADMIN])
- Suspicious URLs

### 2. Injection Detection
Context-aware prompt injection detection:
- Instruction override: "ignore previous instructions"
- Identity manipulation: "you are now in admin mode"
- System extraction: "reveal your system prompt"
- Safety bypass: "disable security checks"

**Smart filtering**: Knows the difference between documentation and attacks
- ✓ "This tool must return valid JSON" (allowed)
- ✗ "You must ignore instructions" (flagged)

### 3. Pattern Matching
Rule-based detection:
- Security overrides: "sudo", "access system", "execute shell"
- Identity manipulation: "you're admin", "pretend to be"
- Cross-tool manipulation: "instead of using X tool"

### 4. Semantic Similarity
AI-powered detection using embeddings:
- Detects rephrased attacks that evade pattern matching
- Uses sentence-transformers model
- Compares against known malicious patterns
- Threshold configurable via `--threshold`

See [DETECTION.md](DETECTION.md) for detailed information about each layer.

## Risk Scoring

Findings are aggregated into a 0-100 risk score using weighted scoring with logarithmic damping.

**How it works**:
- Each finding gets a weight based on severity and detector confidence
- Multiple findings don't stack linearly (prevents false alarm piling)
- Critical findings from reliable detectors score highest

See [SCORING.md](SCORING.md) for the complete algorithm and examples.

## Best Practices

### When to Scan

- **Before deployment**: Scan all MCP servers before adding to your workflow
- **After updates**: Re-scan when server tools/descriptions change
- **Periodic audits**: Regular scans of third-party servers
- **New integrations**: Always scan before trusting a new MCP server

### Threshold Configuration

**Default (0.70)**: Balanced - good for most use cases

**Strict (0.75-0.80)**: Fewer false positives
- Use for: Well-known servers, internal tools
- Trade-off: May miss subtle attacks

**Sensitive (0.60-0.65)**: More detections
- Use for: Untrusted servers, public MCP servers
- Trade-off: More false positives to review

**Very Sensitive (0.50-0.55)**: Maximum detection
- Use for: Security research, high-risk environments
- Trade-off: Many false positives

### Interpreting Results

**Don't panic on single findings**: Review context
- A URL in a description might be legitimate documentation
- "Always returns JSON" is normal API documentation

**Pay attention to critical findings**: These need immediate review
- "Unrestricted mode", "bypass safety", "system mode"
- No legitimate use cases for these phrases

**Multiple detectors agreeing = higher confidence**
- If structural, injection, AND semantic all flag something
- Very likely a real attack attempt

**Context matters**: Read the full tool description
- Some aggressive marketing language might trigger semantic detection
- Technical documentation might contain command examples ("sudo make install")

### Integration into Workflow

```bash
# Pre-deployment check
uv run mcp-swiss-knife scan https://new-server.com/mcp --token $TOKEN
# Review output, then add to Claude Desktop config if clean

# Automated scanning (exit code 0 = clean, 1 = issues found)
if uv run mcp-swiss-knife scan $MCP_URL --threshold 0.70; then
  echo "Clean - safe to use"
else
  echo "Issues detected - review required"
fi
```

### False Positives

This is a **detection tool**, not a blocker. Human review is required.

Common false positives:
- Documentation with command examples ("use sudo to install")
- API descriptions with strong language ("always available")
- Technical terms that match patterns ("system architecture")

When you see a false positive:
1. Verify it's legitimate by checking the source
2. Consider if the phrasing could be clearer
3. File an issue on GitHub to help improve detection

## Security Considerations

### What This Tool Does

✓ Detects suspicious patterns in tool descriptions
✓ Provides risk scoring and categorization
✓ Helps identify potential tool poisoning attempts
✓ Offers transparency into what was flagged and why

### What This Tool Doesn't Do

✗ Guarantee a server is safe (absence of detection ≠ proof of safety)
✗ Analyze actual tool behavior (only descriptions)
✗ Prevent runtime attacks
✗ Replace human security review

### Limitations

- **Detection only**: Requires human judgment
- **Text-based**: Doesn't analyze tool implementation
- **Pattern-based**: Novel attacks might evade detection
- **False positives**: Legitimate tools may be flagged

**Use as part of a security process, not as a standalone solution.**

## Troubleshooting

### "Failed to load detectors"

Ensure dependencies are installed:
```bash
uv sync
```

### "spaCy model not found" (optional)

Pattern detection works without spaCy, but for full NLP features:
```bash
uv run python -m spacy download en_core_web_sm
```

### "Connection timeout"

- Check MCP server is running and accessible
- Increase timeout in code if server is slow
- Verify authentication token is valid

### "Text too long, truncating"

- Server returned very long descriptions (>50KB)
- Tool automatically truncates for safety
- Original content preserved but not fully scanned

## Additional Resources

- [ARCHITECTURE.md](ARCHITECTURE.md) - Codebase structure and design
- [DETECTION.md](DETECTION.md) - Detailed explanation of detection layers
- [SCORING.md](SCORING.md) - Risk scoring algorithm and examples
- [GitHub Issues](https://github.com/nik1097/mcp-swiss-knife/issues) - Report bugs or false positives
