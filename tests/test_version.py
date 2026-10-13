import importlib.metadata
import io

from rich.console import Console

import sentinelscan
import sentinelscan.core
from sentinelscan.config import DEFAULT_UA, VERSION
from sentinelscan.ui.banner import print_banner


def test_version_single_source_of_truth():
    # 1. sentinelscan.__version__ equals config.VERSION
    assert sentinelscan.__version__ == VERSION

    # 2. sentinelscan.core.__version__ equals config.VERSION
    assert sentinelscan.core.__version__ == VERSION

    # 3. DEFAULT_UA contains VERSION
    assert VERSION in DEFAULT_UA

    # 4. Banner output contains VERSION
    buf = io.StringIO()
    test_console = Console(file=buf, force_terminal=False, no_color=True, width=80)
    print_banner(test_console, no_color=True)
    banner_output = buf.getvalue()
    assert f"v{VERSION}" in banner_output

    # 5. Installed package metadata version matches config.VERSION
    try:
        installed_version = importlib.metadata.version("sentinelscan")
        assert installed_version == VERSION
    except importlib.metadata.PackageNotFoundError:
        pass
