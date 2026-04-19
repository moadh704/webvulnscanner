# ── core/colors.py ───────────────────────────────────────────────────────────
"""
Simple ANSI color helper for terminal output.
Automatically disabled on Windows if colorama is not available.
"""

import sys
import os


def _supports_color():
    """Check if terminal supports ANSI colors."""
    if os.name == 'nt':
        try:
            import colorama
            colorama.init(autoreset=True)
            return True
        except ImportError:
            return False
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()


_USE_COLOR = _supports_color()

# ANSI codes
_RESET   = '\033[0m'
_BOLD    = '\033[1m'
_RED     = '\033[91m'
_ORANGE  = '\033[93m'
_YELLOW  = '\033[33m'
_GREEN   = '\033[92m'
_BLUE    = '\033[94m'
_CYAN    = '\033[96m'
_MAGENTA = '\033[95m'
_GRAY    = '\033[90m'
_WHITE   = '\033[97m'


def _c(code: str, text: str) -> str:
    if _USE_COLOR:
        return f"{code}{text}{_RESET}"
    return text


def critical(text: str) -> str: return _c(_BOLD + _RED, text)
def high(text: str)     -> str: return _c(_ORANGE, text)
def medium(text: str)   -> str: return _c(_YELLOW, text)
def low(text: str)      -> str: return _c(_GREEN, text)
def info(text: str)     -> str: return _c(_CYAN, text)
def success(text: str)  -> str: return _c(_GREEN, text)
def warning(text: str)  -> str: return _c(_YELLOW, text)
def bold(text: str)     -> str: return _c(_BOLD, text)
def gray(text: str)     -> str: return _c(_GRAY, text)
def blue(text: str)     -> str: return _c(_BLUE, text)


def severity(sev: str, text: str) -> str:
    """Color text based on severity level."""
    sev_lower = sev.lower()
    if sev_lower == 'critical': return critical(text)
    if sev_lower == 'high':     return high(text)
    if sev_lower == 'medium':   return medium(text)
    if sev_lower == 'low':      return low(text)
    return text


def finding_type(ft: int, text: str) -> str:
    """Color text based on finding type."""
    if ft == 1: return success(text)
    if ft == 2: return warning(text)
    return info(text)
