"""Main CLI interface."""

import logging
import re
from dataclasses import dataclass
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from .config import (
    MAX_TOOLS_PER_SERVER,
    SECRET_PATTERNS,
    LOG_LEVEL,
    HTTP_TIMEOUT,
)
from .mcp_client import MCPClient
from .detector_cache import (
    get_pattern_detector,
    get_semantic_detector,
    get_structural_detector,
    get_injection_detector,
)
from .scoring import RiskScorer

# Configure logging
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

app = typer.Typer(name="mcp-swiss-knife", help="Detect tool poisoning in MCP servers")
console = Console()

PREVIEW_LENGTH = 50
SEPARATOR_WIDTH = 70


def create_progress():
    """Create a progress spinner for loading operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    )


def redact_secrets(text: str) -> str:
    """Redact sensitive information from text."""
    if not text:
        return text

    redacted = text
    for pattern in SECRET_PATTERNS:
        try:
            redacted = re.sub(pattern, "[REDACTED]", redacted)
        except re.error:
            logger.warning(f"Invalid secret pattern: {pattern}")
    return redacted


@dataclass
class TextSource:
    source_type: str
    source_name: str
    text: str

    @property
    def display_name(self) -> str:
        return f"{self.source_type}: {self.source_name}"


def extract_field_descriptions(schema: dict, prefix: str = "") -> list[tuple[str, str]]:
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


@app.command()
def scan(
    url: str = typer.Argument(..., help="MCP server URL"),
    token: Optional[str] = typer.Option(
        None, "--token", "-t", help="Bearer token for authentication"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed detection info"
    ),
    similarity_threshold: float = typer.Option(
        0.70, "--threshold", help="Semantic similarity threshold (0-1)"
    ),
):
    """Scan an MCP server for tool poisoning attempts."""
    # Input validation
    if not url.startswith(("http://", "https://")):
        console.print("[red]✗[/red] URL must start with http:// or https://\n")
        raise typer.Exit(1)

    if not 0.0 <= similarity_threshold <= 1.0:
        console.print("[red]✗[/red] Threshold must be between 0 and 1\n")
        raise typer.Exit(1)

    console.print(
        "\n[bold cyan]MCP Swiss Knife[/bold cyan] - Tool Poisoning Detection\n"
    )
    logger.info(f"Starting scan of {url}")

    try:
        with create_progress() as progress:
            progress.add_task("Loading detectors...", total=None)
            try:
                # Use cached detectors (singleton pattern)
                pattern_detector = get_pattern_detector()
                semantic_detector = get_semantic_detector()
                structural_detector = get_structural_detector()
                injection_detector = get_injection_detector()
                risk_scorer = RiskScorer()
            except Exception as e:
                logger.error(f"Failed to load detectors: {e}")
                console.print(f"[red]✗[/red] Failed to load detectors: {e}\n")
                raise typer.Exit(1)

        console.print("[green]✓[/green] Detectors loaded\n")
        console.print(f"[cyan]→[/cyan] Connecting to MCP server: {url}")

        try:
            client = MCPClient(url, token=token)
        except Exception as e:
            logger.error(f"Failed to create MCP client: {e}")
            console.print(f"[red]✗[/red] Failed to connect: {e}\n")
            raise typer.Exit(1)

        with create_progress() as progress:
            progress.add_task("Fetching tools...", total=None)
            try:
                tools = client.get_tools().get("tools", [])
            except Exception as e:
                logger.error(f"Failed to fetch tools: {e}")
                console.print(f"[red]✗[/red] Failed to fetch tools: {e}\n")
                raise typer.Exit(1)

        if not tools:
            console.print("[yellow]⚠[/yellow] No tools found\n")
            return

        # Validate tool count
        if len(tools) > MAX_TOOLS_PER_SERVER:
            logger.warning(
                f"Too many tools ({len(tools)}), truncating to {MAX_TOOLS_PER_SERVER}"
            )
            console.print(
                f"[yellow]⚠[/yellow] Tool count exceeds limit, analyzing first {MAX_TOOLS_PER_SERVER}\n"
            )
            tools = tools[:MAX_TOOLS_PER_SERVER]

        console.print(f"[green]✓[/green] Found {len(tools)} tool(s)\n")
        logger.info(f"Processing {len(tools)} tools")

        tool_scores = []

        tool_scores = []

        for tool in tools:
            tool_name = tool.get("name", "unknown")

            try:
                console.print(f"\n[bold]Tool:[/bold] [cyan]{tool_name}[/cyan]")

                if verbose:
                    desc = tool.get("description", "")[:100]
                    console.print(f"[dim]Description:[/dim] {desc}...")

                sources = []
                if desc := tool.get("description", ""):
                    sources.append(TextSource("Tool description", tool_name, desc))

                for field_path, field_desc in extract_field_descriptions(
                    tool.get("inputSchema", {})
                ):
                    if field_desc:
                        sources.append(
                            TextSource("Field", f"{tool_name}.{field_path}", field_desc)
                        )

                # Run all detectors with error handling
                pattern_results = []
                semantic_results = []
                structural_results = []
                injection_results = []

                for src in sources:
                    try:
                        pattern_results.extend(
                            [(src, res) for res in pattern_detector.detect(src.text)]
                        )
                    except Exception as e:
                        logger.error(
                            f"Pattern detection failed for {src.display_name}: {e}"
                        )

                    try:
                        semantic_results.extend(
                            [
                                (src, match)
                                for match in semantic_detector.detect(
                                    src.text, similarity_threshold
                                )
                            ]
                        )
                    except Exception as e:
                        logger.error(
                            f"Semantic detection failed for {src.display_name}: {e}"
                        )

                    try:
                        structural_results.extend(
                            [
                                (src, anomaly)
                                for anomaly in structural_detector.detect(src.text)
                            ]
                        )
                    except Exception as e:
                        logger.error(
                            f"Structural detection failed for {src.display_name}: {e}"
                        )

                    try:
                        injection_results.extend(
                            [
                                (src, match)
                                for match in injection_detector.detect(src.text)
                            ]
                        )
                    except Exception as e:
                        logger.error(
                            f"Injection detection failed for {src.display_name}: {e}"
                        )

                # Calculate risk score
                risk_score = risk_scorer.score_tool(
                    tool_name=tool_name,
                    pattern_matches=[r for _, r in pattern_results],
                    semantic_matches=[m for _, m in semantic_results],
                    structural_anomalies=[a for _, a in structural_results],
                    injection_attempts=[m for _, m in injection_results],
                )
                tool_scores.append(risk_score)

                # Display results
                risk_color = {
                    "CRITICAL": "red",
                    "HIGH": "yellow",
                    "MEDIUM": "blue",
                    "LOW": "cyan",
                    "CLEAN": "green",
                }[risk_score.risk_level]

                console.print(
                    f"[bold {risk_color}]Risk: {risk_score.risk_level}[/bold {risk_color}] "
                    f"(Score: {risk_score.overall_score:.1f}/100, Findings: {risk_score.finding_count})\n"
                )

                if risk_score.finding_count > 0:
                    if structural_results:
                        table = Table(title="Structural Anomalies", show_header=True)
                        table.add_column("Source", style="cyan")
                        table.add_column("Type", style="magenta")
                        table.add_column("Severity", style="red")
                        table.add_column("Details", style="yellow")

                        for src, anomaly in structural_results:
                            color = {
                                "critical": "red",
                                "high": "red",
                                "medium": "yellow",
                                "low": "cyan",
                            }[anomaly.severity]
                            details = anomaly.details[:100] + (
                                "..." if len(anomaly.details) > 100 else ""
                            )
                            table.add_row(
                                src.display_name,
                                anomaly.anomaly_type,
                                f"[{color}]{anomaly.severity}[/{color}]",
                                details,
                            )
                        console.print(table)
                        console.print()

                    if injection_results:
                        table = Table(title="Injection Attempts", show_header=True)
                        table.add_column("Source", style="cyan")
                        table.add_column("Category", style="magenta")
                        table.add_column("Severity", style="red")
                        table.add_column("Matched Text", style="yellow")

                        for src, match in injection_results:
                            color = {
                                "critical": "red",
                                "high": "red",
                                "medium": "yellow",
                                "low": "cyan",
                            }[match.severity]
                            # Redact secrets in verbose output
                            text_preview = redact_secrets(match.matched_text)[
                                :PREVIEW_LENGTH
                            ]
                            if len(match.matched_text) > PREVIEW_LENGTH:
                                text_preview += "..."
                            table.add_row(
                                src.display_name,
                                match.category,
                                f"[{color}]{match.severity}[/{color}]",
                                text_preview,
                            )
                        console.print(table)
                        console.print()

                    if pattern_results:
                        table = Table(title="Pattern Detections", show_header=True)
                        table.add_column("Source", style="cyan")
                        table.add_column("Category", style="magenta")
                        table.add_column("Severity", style="red")
                        table.add_column("Matched Text", style="yellow")
                        table.add_column("Confidence", justify="right")

                        for src, result in pattern_results:
                            color = {
                                "critical": "red",
                                "high": "red",
                                "medium": "yellow",
                                "low": "cyan",
                            }[result.severity]
                            # Redact secrets in verbose output
                            text_preview = redact_secrets(result.text)[:PREVIEW_LENGTH]
                            if len(result.text) > PREVIEW_LENGTH:
                                text_preview += "..."
                            table.add_row(
                                src.display_name,
                                result.category,
                                f"[{color}]{result.severity}[/{color}]",
                                text_preview,
                                f"{result.confidence:.2f}",
                            )
                        console.print(table)
                        console.print()

                    if semantic_results:
                        table = Table(
                            title="Semantic Similarity Detections", show_header=True
                        )
                        table.add_column("Source", style="cyan")
                        table.add_column("Category", style="magenta")
                        table.add_column("Severity", style="red")
                        table.add_column("Similar To", style="yellow")
                        table.add_column("Score", justify="right")

                        for src, match in semantic_results:
                            color = {
                                "critical": "red",
                                "high": "red",
                                "medium": "yellow",
                                "low": "cyan",
                            }[match.severity]
                            # Redact secrets in verbose output
                            text_preview = redact_secrets(match.text)[:PREVIEW_LENGTH]
                            if len(match.text) > PREVIEW_LENGTH:
                                text_preview += "..."
                            table.add_row(
                                src.display_name,
                                match.category,
                                f"[{color}]{match.severity}[/{color}]",
                                text_preview,
                                f"{match.similarity_score:.2f}",
                            )
                        console.print(table)
                        console.print()
                else:
                    console.print("[green]✓ No issues detected[/green]")

            except Exception as e:
                logger.error(f"Error processing tool '{tool_name}': {e}")
                console.print(f"[red]✗[/red] Error processing tool: {e}\n")

        # Summary table
        console.print("\n" + "=" * SEPARATOR_WIDTH)
        console.print()

        summary_table = Table(title="Risk Summary", show_header=True)
        summary_table.add_column("Tool", style="cyan")
        summary_table.add_column("Risk Level", justify="center")
        summary_table.add_column("Score", justify="right")
        summary_table.add_column("Findings", justify="right")
        summary_table.add_column("Critical", justify="right", style="red")
        summary_table.add_column("High", justify="right", style="red")
        summary_table.add_column("Medium", justify="right", style="yellow")
        summary_table.add_column("Low", justify="right", style="cyan")

        for score in sorted(tool_scores, key=lambda x: x.overall_score, reverse=True):
            risk_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "cyan",
                "CLEAN": "green",
            }[score.risk_level]

            summary_table.add_row(
                score.tool_name,
                f"[bold {risk_color}]{score.risk_level}[/bold {risk_color}]",
                f"{score.overall_score:.1f}",
                str(score.finding_count),
                str(score.severity_breakdown["critical"]),
                str(score.severity_breakdown["high"]),
                str(score.severity_breakdown["medium"]),
                str(score.severity_breakdown["low"]),
            )

        console.print(summary_table)
        console.print()

        # Overall assessment
        critical_tools = [s for s in tool_scores if s.risk_level == "CRITICAL"]
        high_risk_tools = [s for s in tool_scores if s.risk_level == "HIGH"]
        total_findings = sum(s.finding_count for s in tool_scores)

        if critical_tools:
            console.print(
                Panel(
                    f"[bold red]⚠️  CRITICAL RISK DETECTED[/bold red]\n\n"
                    f"{len(critical_tools)} tool(s) with critical risk level.\n"
                    f"Total findings: {total_findings}\n\n"
                    "Review immediately and consider blocking suspicious tools.",
                    border_style="red",
                )
            )
        elif high_risk_tools:
            console.print(
                Panel(
                    f"[bold yellow]⚠️  HIGH RISK DETECTED[/bold yellow]\n\n"
                    f"{len(high_risk_tools)} tool(s) with high risk level.\n"
                    f"Total findings: {total_findings}\n\n"
                    "Review findings carefully before using these tools.",
                    border_style="yellow",
                )
            )
        elif total_findings > 0:
            console.print(
                Panel(
                    f"[bold blue]Low to medium risk detected[/bold blue]\n\n"
                    f"Total findings: {total_findings}\n\n"
                    "Most tools appear safe. Review flagged items for context.",
                    border_style="blue",
                )
            )
        else:
            console.print(
                Panel(
                    "[bold green]✓ All tools appear clean[/bold green]\n\n"
                    "No suspicious patterns detected.",
                    border_style="green",
                )
            )

    except ValueError as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}\n")
        raise typer.Exit(code=1)
    except Exception as e:
        console.print(f"\n[bold red]Unexpected error:[/bold red] {e}\n")
        raise typer.Exit(code=1)


@app.command()
def version():
    """Show version information."""
    from . import __version__

    console.print(f"MCP Swiss Knife v{__version__}")


if __name__ == "__main__":
    app()
