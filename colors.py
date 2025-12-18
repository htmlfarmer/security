import sys

class Color:
    """A class for colorizing terminal output."""
    def __init__(self):
        # Disable colors if not a TTY (e.g., piping to a file)
        self.enabled = sys.stdout.isatty()

    def _wrap(self, text, code):
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def red(self, text): return self._wrap(text, '31')
    def green(self, text): return self._wrap(text, '32')
    def yellow(self, text): return self._wrap(text, '33')
    def blue(self, text): return self._wrap(text, '34')
    def bold(self, text): return self._wrap(text, '1')

# Singleton instance for easy import
color = Color()
