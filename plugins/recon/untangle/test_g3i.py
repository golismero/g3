import json
import os
import subprocess
import sys

G3I = os.path.join(os.path.dirname(__file__), "g3i.py")


def run_importer(stdin_text, *args):
    proc = subprocess.run(
        [sys.executable, G3I, *args],
        input=stdin_text,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_ordered_three_layers():
    out = run_importer(
        "Layer 1: cloudflare\nLayer 2: varnish\nLayer 3: nginx\n",
        "r", "reversi.nexus",
    )
    assert out == [{
        "_cmd": "untangle https://reversi.nexus/",
        "_fp": ["untangle https://reversi.nexus/"],
        "_artifacts": ["untangle.txt"],
        "url": "https://reversi.nexus/",
        "scheme": "https",
        "host": "reversi.nexus",
        "path": "/",
        "layers": ["cloudflare", "varnish", "nginx"],
    }]


def test_two_layers():
    out = run_importer(
        "Layer 1: nginx\nLayer 2: apache\n",
        "r", "nextcloud.cacharreo.duckdns.org",
    )
    assert out[0]["layers"] == ["nginx", "apache"]


def test_fingerprint_matches_command_for_dedup():
    # The importer's _fp must equal untangle.g3p's command fingerprint
    # ("untangle https://<host>/") exactly, so every url on a host and the bare
    # domain dedup to one run (scanner dedups by exact _fp string match).
    out = run_importer("Layer 1: nginx\n", "r", "reversi.nexus")
    assert out[0]["_fp"] == ["untangle https://reversi.nexus/"]
    assert out[0]["_cmd"] == "untangle https://reversi.nexus/"
    assert out[0]["url"] == "https://reversi.nexus/"


def test_trailing_unknown_is_dropped():
    out = run_importer(
        "Layer 1: cloudflare\nLayer 2: varnish\nLayer 3: unknown\n",
        "r", "www.example.net",
    )
    assert out[0]["layers"] == ["cloudflare", "varnish"]


def test_too_long_yields_empty():
    out = run_importer("Layer 1: too_long\n", "r", "1.1.1.1")
    assert out == []


def test_exception_with_debug_noise_yields_empty():
    out = run_importer(
        "[Errno 61] Connection refused\nLayer 1: exception\n",
        "r", "host.invalid",
    )
    assert out == []


def test_unordered_layers_are_collected():
    out = run_importer(
        "Unordered Layers:\nnginx\napache\n",
        "r", "example.org",
    )
    assert out[0]["layers"] == ["nginx", "apache"]


def test_debug_noise_after_unordered_header_is_filtered():
    out = run_importer(
        "Unordered Layers:\nnginx\nsomething wrong\napache\n",
        "r", "example.org",
    )
    assert out[0]["layers"] == ["nginx", "apache"]


def test_import_mode_without_host_yields_empty():
    out = run_importer("Layer 1: nginx\n")
    assert out == []


def test_run_mode_without_host_yields_empty():
    out = run_importer("Layer 1: nginx\n", "r")
    assert out == []
