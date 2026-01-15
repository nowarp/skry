"""
Jinja2 template-based prompt generation.

All LLM prompts are stored as .j2 templates in this directory.
Use render() to generate prompts with template variables.
"""

from jinja2 import Environment, FileSystemLoader
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def _simple_name(fqn: str) -> str:
    """Extract simple name from fully qualified name (e.g., 'mod::Struct' -> 'Struct')."""
    if "::" in fqn:
        return fqn.split("::")[-1]
    return fqn


_env = Environment(
    loader=FileSystemLoader(_PROMPTS_DIR),
    autoescape=False,  # No HTML escaping for prompts
    trim_blocks=True,
    lstrip_blocks=True,
)
_env.filters["simple_name"] = _simple_name


def render(template_name: str, **kwargs) -> str:
    """Render a prompt template with given parameters.

    Args:
        template_name: Path relative to prompts dir (e.g., "vuln/access_control.j2")
        **kwargs: Template variables

    Returns:
        Rendered prompt string
    """
    template = _env.get_template(template_name)
    return template.render(**kwargs)
