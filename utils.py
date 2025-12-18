# Shared utility functions and classes.

class Colors:
    """A simple class for adding color to terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    @staticmethod
    def print_fail(message):
        print(f"{Colors.FAIL}{message}{Colors.ENDC}")

    @staticmethod
    def print_warning(message):
        print(f"{Colors.WARNING}{message}{Colors.ENDC}")

    @staticmethod
    def print_header(message):
        print(f"\n{Colors.HEADER}{Colors.BOLD}{message}{Colors.ENDC}")

    @staticmethod
    def print_info(message):
        print(f"{Colors.OKBLUE}{message}{Colors.ENDC}")
