"""Optional Textual dashboard for --interactive mode."""
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, DataTable, Static, Log
from textual.containers import Horizontal, Vertical


class ScanDashboard(App):
    CSS = """
    Screen { background: #0d1117; }
    #summary { height: 7; border: solid #30363d; }
    DataTable { height: 1fr; }
    #log { height: 12; border: solid #30363d; }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("s", "save", "Save report"),
        ("f", "filter", "Filter"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield Static("Waiting for scan...", id="summary")
        yield DataTable(id="findings")
        yield Log(id="log")
        yield Footer()

    def on_mount(self):
        table = self.query_one(DataTable)
        table.add_columns("Sev", "Module", "Title", "URL")

    def push_finding(self, finding):
        table = self.query_one(DataTable)
        table.add_row(finding.severity.name, finding.module,
                      finding.title, finding.url or "-")
        self.query_one(Log).write_line(f"[{finding.severity.name}] {finding.title}")