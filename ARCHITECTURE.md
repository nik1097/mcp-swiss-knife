# Architecture

## Overview

MCP Swiss Knife is a security tool that scans MCP servers for "tool poisoning" - malicious attempts to inject harmful instructions into AI tool descriptions.

## Module Structure

### Core Modules

#### [main.py](mcp_swiss_knife/main.py) - CLI Entry Point
- **Purpose**: Command-line interface using Typer
- **Key Functions**:
  - `scan()`: Main command that orchestrates the entire scanning process
  - `create_progress()`: Rich progress spinners for UX
  - `redact_secrets()`: Removes API keys and tokens from output
  - `extract_field_descriptions()`: Recursively parses JSON schemas
- **Flow**: Loads detectors → Connects to MCP server → Runs 4 detection passes → Scores risk → Displays results

#### [mcp_client.py](mcp_swiss_knife/mcp_client.py) - MCP Communication
- **Purpose**: HTTP client for JSON-RPC 2.0 over Server-Sent Events (SSE)
- **Key Features**:
  - Handles authentication (Bearer tokens)
  - Parses SSE response streams
  - Enforces `MAX_TOOLS_PER_SERVER` limit (prevents memory exhaustion)
  - Validates response structure
- **Main Method**: `get_tools()` - fetches all tools from the server

#### [config.py](mcp_swiss_knife/config.py) - Configuration
- **Purpose**: Central configuration and security limits
- **Key Settings**:
  - Input limits (50KB max text, 1000 tools max)
  - Detection thresholds (0.70 semantic similarity)
  - Detector weights (structural=0.9, injection=0.85)
  - Severity weights (critical=1.0, low=0.25)
  - Secret patterns for redaction

### Detection Engines (4 Layers)

#### [injection_detector.py](mcp_swiss_knife/injection_detector.py) - Prompt Injection Detection
- **Purpose**: Context-aware detection of prompt injection attacks
- **Intelligence**:
  - **Documentation Allow-List**: Skips phrases like "use this tool to..." (legitimate)
  - **Critical Patterns**: Always flagged (e.g., "system mode activated", "bypass safety")
  - **Regular Patterns**: Checked against documentation allow-list
- **ReDoS Protection**: Simplified regex patterns, no nested quantifiers
- **Example Detections**:
  - "ignore previous instructions"
  - "you are now in admin mode"
  - "reveal your system prompt"

#### [pattern_detector.py](mcp_swiss_knife/pattern_detector.py) - Rule-Based Matching
- **Purpose**: Pattern matching using regex + optional spaCy NLP
- **Detection Categories**:
  - Security overrides ("access system", "sudo", "bypass security")
  - Identity manipulation ("you're admin", "pretend to be")
  - Cross-tool manipulation ("instead of using X tool")
- **Dual Approach**:
  - Regex patterns (always available)
  - spaCy linguistic patterns (optional, if installed)
- **False Positive Reduction**: Context-dependent patterns (e.g., proximity checks)

#### [semantic_detector.py](mcp_swiss_knife/semantic_detector.py) - AI-Powered Similarity
- **Purpose**: Detects semantically similar malicious patterns using embeddings
- **Model**: `all-MiniLM-L6-v2` (sentence-transformers)
- **Poisoning Categories** (6 types with example phrases):
  - Instruction Override
  - Identity Manipulation
  - System Extraction
  - Safety Bypass
  - Data Manipulation
- **How It Works**:
  - Pre-encodes malicious example phrases
  - Compares input text embeddings using cosine similarity
  - Flags matches above threshold (default 0.70)

#### [structural_detector.py](mcp_swiss_knife/structural_detector.py) - Anomaly Detection
- **Purpose**: Detects obfuscation and structural attacks
- **Detection Types**:
  - **Length Attacks**: Descriptions over 1000 chars (drowns out warnings)
  - **Unicode Tricks**: Zero-width chars, control characters
  - **Encoding**: Base64/hex encoded payloads
  - **Delimiter Injection**: "```system", "---override", "[SYSTEM]"
  - **URLs**: Potential data exfiltration endpoints
  - **Whitespace Abuse**: Excessive newlines/spaces

### Supporting Modules

#### [scoring.py](mcp_swiss_knife/scoring.py) - Risk Scoring
- **Purpose**: Aggregates findings into a 0-100 risk score
- **Algorithm**:
  - Weighted sum: `severity_weight × detector_weight`
  - Logarithmic damping: Prevents single finding from dominating
  - Risk levels: CRITICAL (75+), HIGH (50+), MEDIUM (25+), LOW (<25)
- **Output**: Severity breakdown + detector breakdown

#### [detector_cache.py](mcp_swiss_knife/detector_cache.py) - Singleton Pattern
- **Purpose**: Lazy-loads detectors once per session (expensive model loading)
- **Functions**:
  - `get_pattern_detector()`
  - `get_semantic_detector()` (loads ML model)
  - `get_structural_detector()`
  - `get_injection_detector()`
- **Benefit**: Avoids reloading spaCy/sentence-transformers models

#### [normalizer.py](mcp_swiss_knife/normalizer.py) - Text Preprocessing
- **Purpose**: Standardizes text for consistent pattern matching
- **Operations**:
  - Lowercase conversion
  - Unicode normalization (NFD)
  - Removes diacritics
  - Collapses whitespace

## Security Architecture

1. **Defense in Depth**: 4 independent detection layers (structural → injection → pattern → semantic)
2. **ReDoS Protection**: All regex patterns validated, no nested quantifiers, input length limits
3. **False Positive Reduction**: Context-aware allow-lists, higher thresholds
4. **Resource Limits**: Tool count limits, text length truncation, timeout enforcement
5. **Secret Redaction**: Automatically removes API keys from output

## Data Flow

```
User → CLI (main.py)
  → Load Detectors (detector_cache.py)
  → Fetch Tools (mcp_client.py)
  → For each tool description:
      → Structural Check (structural_detector.py)
      → Injection Check (injection_detector.py)
      → Pattern Match (pattern_detector.py)
      → Semantic Match (semantic_detector.py)
  → Aggregate Risk Score (scoring.py)
  → Display Results (Rich formatting)
```

## Design Principles

- **Detection-only**: Requires human review, not an automatic blocker
- **Transparency**: Shows exactly what was detected and why
- **Configurable**: Adjustable thresholds for different risk tolerances
- **Performant**: Singleton pattern, caching, input validation
- **Maintainable**: Modular design, clear separation of concerns
