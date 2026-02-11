#!/usr/bin/env python3
"""Test script for malicious MCP server detection."""

import json
from mcp_swiss_knife.pattern_detector import PatternDetector
from mcp_swiss_knife.semantic_detector import SemanticDetector
from mcp_swiss_knife.structural_detector import StructuralDetector
from mcp_swiss_knife.injection_detector import InjectionDetector
from mcp_swiss_knife.scoring import RiskScorer


def extract_field_descriptions(schema, prefix=""):
    """Recursively extract field descriptions from schema."""
    if not isinstance(schema, dict):
        return []

    descriptions = []
    if "description" in schema:
        descriptions.append((prefix or "root", schema["description"]))

    if "properties" in schema:
        for field_name, field_schema in schema["properties"].items():
            field_path = f"{prefix}.{field_name}" if prefix else field_name
            descriptions.extend(extract_field_descriptions(field_schema, field_path))

    if "items" in schema:
        items_path = f"{prefix}[]" if prefix else "[]"
        descriptions.extend(extract_field_descriptions(schema["items"], items_path))

    return descriptions


def test_malicious_server():
    print("\n" + "=" * 70)
    print("Testing MCP Swiss Knife with Malicious Server")
    print("=" * 70 + "\n")

    # Load mock server response
    with open("test_malicious_server.json") as f:
        data = json.load(f)

    # Initialize detectors
    print("Loading detectors...")
    pattern_detector = PatternDetector()
    semantic_detector = SemanticDetector()
    structural_detector = StructuralDetector()
    injection_detector = InjectionDetector()
    risk_scorer = RiskScorer()
    print("✓ Detectors loaded\n")

    tools = data.get("tools", [])
    print(f"Found {len(tools)} tool(s)\n")

    for tool in tools:
        tool_name = tool.get("name", "unknown")
        print(f"\n{'='*70}")
        print(f"Tool: {tool_name}")
        print("=" * 70)

        # Collect all text sources
        texts = []
        if desc := tool.get("description", ""):
            texts.append(("description", desc))

        for field_path, field_desc in extract_field_descriptions(
            tool.get("inputSchema", {})
        ):
            texts.append((f"field:{field_path}", field_desc))

        # Run all detectors
        all_pattern = []
        all_semantic = []
        all_structural = []
        all_injection = []

        for source, text in texts:
            all_pattern.extend(pattern_detector.detect(text))
            all_semantic.extend(semantic_detector.detect(text, threshold=0.70))
            all_structural.extend(structural_detector.detect(text))
            all_injection.extend(injection_detector.detect(text))

        # Calculate risk
        risk = risk_scorer.score_tool(
            tool_name=tool_name,
            pattern_matches=all_pattern,
            semantic_matches=all_semantic,
            structural_anomalies=all_structural,
            injection_attempts=all_injection,
        )

        # Display results
        print(f"\n🎯 RISK LEVEL: {risk.risk_level}")
        print(f"📊 Score: {risk.overall_score:.1f}/100")
        print(f"🔍 Total Findings: {risk.finding_count}")
        print(f"\nBreakdown:")
        print(f"  • Critical: {risk.severity_breakdown['critical']}")
        print(f"  • High:     {risk.severity_breakdown['high']}")
        print(f"  • Medium:   {risk.severity_breakdown['medium']}")
        print(f"  • Low:      {risk.severity_breakdown['low']}")

        print(f"\nDetector Results:")
        print(f"  • Structural: {risk.detector_breakdown['structural']} findings")
        print(f"  • Injection:  {risk.detector_breakdown['injection']} findings")
        print(f"  • Pattern:    {risk.detector_breakdown['pattern']} findings")
        print(f"  • Semantic:   {risk.detector_breakdown['semantic']} findings")

        if risk.finding_count > 0:
            print("\n📋 Detailed Findings:")

            if all_structural:
                print("\n  Structural Anomalies:")
                for anom in all_structural:
                    print(f"    ⚠️  [{anom.severity.upper()}] {anom.anomaly_type}")
                    print(f"        {anom.details}")

            if all_injection:
                print("\n  Injection Attempts:")
                for inj in all_injection:
                    print(f"    ⚠️  [{inj.severity.upper()}] {inj.injection_type}")
                    print(f"        {inj.details[:100]}...")

            if all_pattern:
                print("\n  Pattern Detections:")
                for pat in all_pattern:
                    print(f"    ⚠️  [{pat.severity.upper()}] {pat.category}")
                    print(f"        Text: {pat.text[:80]}...")

            if all_semantic:
                print("\n  Semantic Matches:")
                for sem in all_semantic:
                    print(f"    ⚠️  [{sem.severity.upper()}] {sem.category}")
                    print(f"        Similar to: {sem.reference_text}")
                    print(f"        Score: {sem.similarity_score:.3f}")

    print("\n" + "=" * 70)
    print("Test Complete")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    test_malicious_server()
