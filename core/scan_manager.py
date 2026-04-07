# ── core/scan_manager.py ─────────────────────────────────────────────────────

ALL_MODULES = ['sqli', 'xss', 'cmdi', 'traversal', 'idor', 'headers']


class ScanManager:
    """
    Reads the --scan flag and builds the active module list.
    If no flag is provided, all modules are activated by default.
    """

    def __init__(self, scan_flag=None):
        if scan_flag is None:
            self.active = ALL_MODULES[:]          # full scan by default
        else:
            requested   = [m.strip().lower() for m in scan_flag.split(',')]
            self.active = [m for m in requested if m in ALL_MODULES]

            if not self.active:
                print(f"[!] Warning: no valid modules in --scan '{scan_flag}'")
                print(f"    Valid options: {', '.join(ALL_MODULES)}")
                print(f"    Running full scan instead.")
                self.active = ALL_MODULES[:]

    def is_active(self, module_name: str) -> bool:
        return module_name in self.active

    def active_modules(self) -> list:
        return self.active[:]

    def __repr__(self):
        return f"ScanManager(active={self.active})"
