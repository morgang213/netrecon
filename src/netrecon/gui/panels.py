"""Tool panel widgets for the NetRecon GUI."""

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from netrecon.explain import EXPLANATIONS
from netrecon.gui.workers import ToolWorker, strip_rich_tags

# ── Authorization ────────────────────────────────────────────

ACTIVE_WARNING = (
    "AUTHORIZATION WARNING\n\n"
    "This tool sends network traffic to the target system.\n"
    "Only use against systems you own or have "
    "explicit written permission to test.\n\n"
    "Unauthorized scanning may violate laws in your jurisdiction."
)

ACTIVE_TOOLS = {
    "port_scanner",
    "ping_sweep",
    "dns_lookup",
    "traceroute",
    "banner_grab",
    "ssl_checker",
}


def _confirm_active(parent) -> bool:
    result = QMessageBox.warning(
        parent,
        "Authorization Required",
        ACTIVE_WARNING,
        QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel,
    )
    return result == QMessageBox.StandardButton.Ok


# ── Base Panel ───────────────────────────────────────────────


class ToolPanel(QWidget):
    """Base class for all tool panels."""

    tool_name: str = ""
    tool_label: str = ""
    is_active: bool = False

    def __init__(self, status_bar=None, parent=None):
        super().__init__(parent)
        self._worker = None
        self._status_bar = status_bar
        self._setup_ui()

    # ── UI construction ──────────────────────────────────────

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 8)

        # Title
        title = QLabel(self.tool_label)
        title.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(title)

        # Active badge
        if self.is_active:
            badge = QLabel("⚡ Active tool — sends network traffic")
            badge.setStyleSheet(
                "color: #e67e22; font-size: 11px; margin-bottom: 4px;"
            )
            layout.addWidget(badge)

        # Explanation toggle
        self._explain_btn = QPushButton("▸ What is this tool?")
        self._explain_btn.setFlat(True)
        self._explain_btn.setStyleSheet(
            "text-align: left; color: #3498db; font-size: 12px;"
        )
        self._explain_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._explain_btn.setCheckable(True)
        self._explain_btn.toggled.connect(self._toggle_explanation)
        layout.addWidget(self._explain_btn)

        info = EXPLANATIONS.get(self.tool_name, {})
        body = info.get("body", "")
        learn = info.get("learn_more", "")
        explain_html = body.replace("\n", "<br>")
        if learn:
            explain_html += (
                f'<br><br><a href="{learn}"'
                f' style="color:#3498db;">Learn more →</a>'
            )
        self._explain_text = QLabel(explain_html)
        self._explain_text.setWordWrap(True)
        self._explain_text.setOpenExternalLinks(True)
        self._explain_text.setStyleSheet(
            "background: #f0f4f8; padding: 10px; border-radius: 6px;"
            "margin-bottom: 8px; font-size: 12px; color: #333;"
        )
        self._explain_text.setVisible(False)
        layout.addWidget(self._explain_text)

        # Input form
        self._form = QFormLayout()
        self._form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        self._build_inputs()
        layout.addLayout(self._form)

        # Run button
        self._run_btn = QPushButton(f"▶  Run {self.tool_label}")
        self._run_btn.setStyleSheet(
            "QPushButton { background: #2ecc71; color: white;"
            "font-weight: bold; padding: 8px 20px; border-radius: 4px;"
            "font-size: 13px; }"
            "QPushButton:hover { background: #27ae60; }"
            "QPushButton:disabled { background: #95a5a6; }"
        )
        self._run_btn.clicked.connect(self._on_run)
        layout.addWidget(self._run_btn)

        # Progress bar (indeterminate, hidden by default)
        self._progress = QProgressBar()
        self._progress.setRange(0, 0)
        self._progress.setVisible(False)
        self._progress.setMaximumHeight(4)
        self._progress.setTextVisible(False)
        layout.addWidget(self._progress)

        # Results
        self._results = QTextEdit()
        self._results.setReadOnly(True)
        self._results.setFont(QFont("Menlo, Consolas, monospace", 11))
        self._results.setStyleSheet(
            "background: #1e1e1e; color: #d4d4d4; padding: 8px;"
            "border-radius: 4px;"
        )
        self._results.setPlaceholderText("Results will appear here…")
        layout.addWidget(self._results, stretch=1)

    def _toggle_explanation(self, checked: bool):
        self._explain_text.setVisible(checked)
        arrow = "▾" if checked else "▸"
        self._explain_btn.setText(f"{arrow} What is this tool?")

    # ── Abstract methods (subclass must implement) ───────────

    def _build_inputs(self):
        raise NotImplementedError

    def _collect_inputs(self) -> dict:
        raise NotImplementedError

    def _execute(self, inputs: dict):
        raise NotImplementedError

    def _format_result(self, result) -> str:
        raise NotImplementedError

    # ── Run / result handling ────────────────────────────────

    def _on_run(self):
        if self.is_active and not _confirm_active(self):
            return

        try:
            inputs = self._collect_inputs()
        except (ValueError, TypeError) as e:
            self._show_error(f"Input error: {e}")
            return

        self._run_btn.setEnabled(False)
        self._progress.setVisible(True)
        self._results.clear()
        if self._status_bar:
            self._status_bar.showMessage(f"Running {self.tool_label}…")

        self._worker = ToolWorker(self._execute, inputs)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_finished(self, result):
        self._run_btn.setEnabled(True)
        self._progress.setVisible(False)
        text = self._format_result(result)
        self._results.setPlainText(text)
        if self._status_bar:
            self._status_bar.showMessage(
                f"{self.tool_label} complete.", 5000
            )

    def _on_error(self, msg: str):
        self._run_btn.setEnabled(True)
        self._progress.setVisible(False)
        self._show_error(msg)
        if self._status_bar:
            self._status_bar.showMessage(
                f"{self.tool_label} failed.", 5000
            )

    def _show_error(self, msg: str):
        cleaned = strip_rich_tags(msg)
        self._results.setHtml(
            f'<p style="color: #e74c3c; font-family: monospace;">'
            f"Error: {cleaned}</p>"
        )


# ── Concrete Panels ─────────────────────────────────────────


class SubnetCalcPanel(ToolPanel):
    tool_name = "subnet_calc"
    tool_label = "Subnet Calculator"
    is_active = False

    def _build_inputs(self):
        self._network = QLineEdit()
        self._network.setPlaceholderText("192.168.1.0/24")
        self._form.addRow("Network (CIDR):", self._network)

    def _collect_inputs(self):
        v = self._network.text().strip()
        if not v:
            raise ValueError("Enter a network in CIDR notation.")
        return {"network": v}

    def _execute(self, inputs):
        from netrecon.tools.subnet_calc import calculate_subnet

        return calculate_subnet(inputs["network"])

    def _format_result(self, r):
        labels = {
            "network": "Network Address",
            "broadcast": "Broadcast Address",
            "netmask": "Subnet Mask",
            "wildcard": "Wildcard Mask",
            "prefix_length": "Prefix Length",
            "total_addresses": "Total Addresses",
            "usable_hosts": "Usable Hosts",
            "first_host": "First Usable Host",
            "last_host": "Last Usable Host",
            "version": "IP Version",
            "is_private": "Private Network",
        }
        lines = []
        for key, label in labels.items():
            val = r.get(key, "")
            if key == "prefix_length":
                val = f"/{val}"
            elif key == "version":
                val = f"IPv{val}"
            elif key == "is_private":
                val = "Yes" if val else "No"
            elif isinstance(val, int):
                val = f"{val:,}"
            lines.append(f"{label:>20s}:  {val}")
        return "\n".join(lines)

    def _on_run(self):
        """Subnet calc is instant — run synchronously."""
        try:
            inputs = self._collect_inputs()
        except ValueError as e:
            self._show_error(str(e))
            return
        try:
            result = self._execute(inputs)
            self._results.setPlainText(self._format_result(result))
            if self._status_bar:
                self._status_bar.showMessage("Subnet calculated.", 3000)
        except Exception as e:
            self._show_error(strip_rich_tags(str(e)))


class PortScannerPanel(ToolPanel):
    tool_name = "port_scanner"
    tool_label = "Port Scanner"
    is_active = True

    def _build_inputs(self):
        self._target = QLineEdit()
        self._target.setPlaceholderText("192.168.1.1 or example.com")
        self._form.addRow("Target:", self._target)

        port_row = QHBoxLayout()
        self._ports = QLineEdit("1-1024")
        self._preset = QComboBox()
        self._preset.addItems(
            ["Custom", "Top 20", "Web", "Database", "Mail"]
        )
        self._preset.currentTextChanged.connect(self._on_preset)
        port_row.addWidget(self._ports, stretch=1)
        port_row.addWidget(self._preset)
        self._form.addRow("Ports:", port_row)

        self._timeout = QDoubleSpinBox()
        self._timeout.setRange(0.1, 30.0)
        self._timeout.setValue(1.0)
        self._timeout.setSuffix(" sec")
        self._form.addRow("Timeout:", self._timeout)

        self._threads = QSpinBox()
        self._threads.setRange(1, 500)
        self._threads.setValue(100)
        self._form.addRow("Threads:", self._threads)

    def _on_preset(self, text):
        from netrecon.utils import PORT_PRESETS

        key = text.lower().replace(" ", "-")
        if key in PORT_PRESETS:
            self._ports.setText(PORT_PRESETS[key])

    def _collect_inputs(self):
        target = self._target.text().strip()
        if not target:
            raise ValueError("Enter a target host.")
        return {
            "target": target,
            "ports": self._ports.text().strip(),
            "timeout": self._timeout.value(),
            "threads": self._threads.value(),
        }

    def _execute(self, inputs):
        from netrecon.tools.port_scanner import scan_ports
        from netrecon.utils import parse_port_range, validate_host

        host = validate_host(inputs["target"])
        port_list = parse_port_range(inputs["ports"])
        results = scan_ports(
            host, port_list, inputs["timeout"], inputs["threads"]
        )
        return {"host": host, "target": inputs["target"], "results": results}

    def _format_result(self, data):
        from netrecon.utils import get_service_info

        results = data["results"]
        addr = (
            f"{data['target']} ({data['host']})"
            if data["target"] != data["host"]
            else data["host"]
        )
        lines = [f"Scan results for {addr}", ""]
        lines.append(
            f"{'Port':<12}{'State':<12}{'Service':<14}Description"
        )
        lines.append("─" * 58)

        for port in sorted(results):
            state = results[port]
            if state == "closed":
                continue
            svc, desc = get_service_info(port)
            lines.append(f"{port}/tcp{'':<5}{state:<12}{svc:<14}{desc}")

        o = sum(1 for s in results.values() if s == "open")
        c = sum(1 for s in results.values() if s == "closed")
        f = sum(1 for s in results.values() if s == "filtered")
        lines.append("")
        lines.append(
            f"Done: {o} open, {c} closed, {f} filtered "
            f"({len(results)} ports)"
        )
        return "\n".join(lines)


class DnsLookupPanel(ToolPanel):
    tool_name = "dns_lookup"
    tool_label = "DNS Lookup"
    is_active = True

    def _build_inputs(self):
        self._domain = QLineEdit()
        self._domain.setPlaceholderText("example.com")
        self._form.addRow("Domain:", self._domain)

        types_row = QHBoxLayout()
        self._type_checks = {}
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            cb = QCheckBox(rtype)
            cb.setChecked(rtype in ("A", "AAAA", "MX", "NS", "TXT"))
            self._type_checks[rtype] = cb
            types_row.addWidget(cb)
        self._form.addRow("Record types:", types_row)

        self._server = QLineEdit()
        self._server.setPlaceholderText("(optional) e.g. 8.8.8.8")
        self._form.addRow("DNS Server:", self._server)

    def _collect_inputs(self):
        domain = self._domain.text().strip()
        if not domain:
            raise ValueError("Enter a domain name.")
        types = [
            t for t, cb in self._type_checks.items() if cb.isChecked()
        ]
        if not types:
            raise ValueError("Select at least one record type.")
        server = self._server.text().strip() or None
        return {"domain": domain, "types": types, "server": server}

    def _execute(self, inputs):
        from netrecon.tools.dns_lookup import query_dns

        return query_dns(
            inputs["domain"], inputs["types"], inputs["server"]
        )

    def _format_result(self, results):
        from netrecon.tools.dns_lookup import RECORD_DESCRIPTIONS

        lines = [f"{'Type':<8}{'Value':<40}Description"]
        lines.append("─" * 70)
        for rtype, values in results.items():
            desc = RECORD_DESCRIPTIONS.get(rtype, "")
            if not values:
                lines.append(f"{rtype:<8}{'(no records)':<40}{desc}")
            else:
                for i, v in enumerate(values):
                    lines.append(
                        f"{rtype if i == 0 else '':<8}{v:<40}"
                        f"{desc if i == 0 else ''}"
                    )
        return "\n".join(lines)


class PingSweepPanel(ToolPanel):
    tool_name = "ping_sweep"
    tool_label = "Ping Sweep"
    is_active = True

    def _build_inputs(self):
        self._network = QLineEdit()
        self._network.setPlaceholderText("192.168.1.0/24")
        self._form.addRow("Network (CIDR):", self._network)

        self._timeout = QSpinBox()
        self._timeout.setRange(1, 10)
        self._timeout.setValue(1)
        self._timeout.setSuffix(" sec")
        self._form.addRow("Timeout:", self._timeout)

        self._threads = QSpinBox()
        self._threads.setRange(1, 200)
        self._threads.setValue(50)
        self._form.addRow("Threads:", self._threads)

    def _collect_inputs(self):
        net = self._network.text().strip()
        if not net:
            raise ValueError("Enter a network in CIDR notation.")
        return {
            "network": net,
            "timeout": self._timeout.value(),
            "threads": self._threads.value(),
        }

    def _execute(self, inputs):
        from netrecon.tools.ping_sweep import sweep_network

        return sweep_network(
            inputs["network"], inputs["timeout"], inputs["threads"]
        )

    def _format_result(self, results):
        alive = [(ip, s) for ip, s in results if s]
        lines = [
            f"{'IP Address':<20}Status",
            "─" * 30,
        ]
        for ip, _ in alive:
            lines.append(f"{ip:<20}alive")
        lines.append("")
        lines.append(
            f"{len(alive)} hosts alive out of {len(results)} scanned"
        )
        return "\n".join(lines)


class BannerGrabPanel(ToolPanel):
    tool_name = "banner_grab"
    tool_label = "Banner Grab"
    is_active = True

    def _build_inputs(self):
        self._target = QLineEdit()
        self._target.setPlaceholderText("192.168.1.1 or example.com")
        self._form.addRow("Target:", self._target)

        self._ports = QLineEdit("21,22,25,80,110,143,443,3306,5432,8080")
        self._form.addRow("Ports:", self._ports)

        self._timeout = QDoubleSpinBox()
        self._timeout.setRange(0.5, 30.0)
        self._timeout.setValue(3.0)
        self._timeout.setSuffix(" sec")
        self._form.addRow("Timeout:", self._timeout)

    def _collect_inputs(self):
        target = self._target.text().strip()
        if not target:
            raise ValueError("Enter a target host.")
        return {
            "target": target,
            "ports": self._ports.text().strip(),
            "timeout": self._timeout.value(),
        }

    def _execute(self, inputs):
        from netrecon.tools.banner_grab import grab_banners
        from netrecon.utils import parse_port_range, validate_host

        host = validate_host(inputs["target"])
        port_list = parse_port_range(inputs["ports"])
        results = grab_banners(host, port_list, inputs["timeout"])
        return {"host": host, "results": results}

    def _format_result(self, data):
        from netrecon.utils import get_service_info

        results = data["results"]
        lines = [
            f"{'Port':<12}{'Service':<14}Banner",
            "─" * 60,
        ]
        for port in sorted(results):
            banner = results[port]
            svc, _ = get_service_info(port)
            display = banner[:120] if banner else "(no banner)"
            lines.append(f"{port}/tcp{'':<5}{svc:<14}{display}")
        return "\n".join(lines)


class WhoisPanel(ToolPanel):
    tool_name = "whois_lookup"
    tool_label = "WHOIS Lookup"
    is_active = False

    def _build_inputs(self):
        self._target = QLineEdit()
        self._target.setPlaceholderText("example.com or 8.8.8.8")
        self._form.addRow("Domain / IP:", self._target)

    def _collect_inputs(self):
        v = self._target.text().strip()
        if not v:
            raise ValueError("Enter a domain or IP address.")
        return {"target": v}

    def _execute(self, inputs):
        from netrecon.tools.whois_lookup import query_whois

        return query_whois(inputs["target"])

    def _format_result(self, r):
        lines = []
        fields = [
            ("Domain", "domain"),
            ("Registrar", "registrar"),
            ("Organization", "org"),
            ("Country", "country"),
            ("Created", "creation_date"),
            ("Expires", "expiration_date"),
            ("Updated", "updated_date"),
        ]
        for label, key in fields:
            lines.append(f"{label:>16s}:  {r.get(key, 'N/A')}")

        ns = r.get("name_servers", [])
        if ns:
            lines.append(f"{'Name Servers':>16s}:  {', '.join(str(s) for s in ns[:5])}")

        emails = r.get("emails", [])
        if emails:
            lines.append(
                f"{'Emails':>16s}:  "
                f"{', '.join(str(e) for e in emails)}"
            )
        return "\n".join(lines)


class HeaderInspectorPanel(ToolPanel):
    tool_name = "header_inspector"
    tool_label = "HTTP Headers"
    is_active = False

    def _build_inputs(self):
        self._url = QLineEdit()
        self._url.setPlaceholderText("example.com or https://example.com")
        self._form.addRow("URL:", self._url)

    def _collect_inputs(self):
        v = self._url.text().strip()
        if not v:
            raise ValueError("Enter a URL.")
        return {"url": v}

    def _execute(self, inputs):
        from netrecon.tools.header_inspector import (
            analyze_security_headers,
            fetch_headers,
        )

        data = fetch_headers(inputs["url"])
        findings = analyze_security_headers(data["headers"])
        return {"data": data, "findings": findings}

    def _format_result(self, r):
        data = r["data"]
        findings = r["findings"]
        lines = [
            f"URL: {data['url']}  (HTTP {data['status_code']})",
            "",
            "── Security Header Analysis ──",
            "",
            f"{'Header':<40}{'Status':<10}Description",
            "─" * 75,
        ]
        present = 0
        for f in findings:
            status = "Present" if f["present"] else "MISSING"
            if f["present"]:
                present += 1
            lines.append(f"{f['header']:<40}{status:<10}{f['desc']}")

        lines.append("")
        lines.append(
            f"Score: {present}/{len(findings)} security headers present"
        )

        lines.append("")
        lines.append("── All Response Headers ──")
        lines.append("")
        for k, v in sorted(data["headers"].items()):
            lines.append(f"  {k}: {v[:100]}")
        return "\n".join(lines)


class SslCheckerPanel(ToolPanel):
    tool_name = "ssl_checker"
    tool_label = "SSL/TLS Checker"
    is_active = True

    def _build_inputs(self):
        self._host = QLineEdit()
        self._host.setPlaceholderText("example.com")
        self._form.addRow("Host:", self._host)

        self._port = QSpinBox()
        self._port.setRange(1, 65535)
        self._port.setValue(443)
        self._form.addRow("Port:", self._port)

        self._timeout = QDoubleSpinBox()
        self._timeout.setRange(1.0, 30.0)
        self._timeout.setValue(5.0)
        self._timeout.setSuffix(" sec")
        self._form.addRow("Timeout:", self._timeout)

    def _collect_inputs(self):
        host = self._host.text().strip()
        if not host:
            raise ValueError("Enter a hostname.")
        return {
            "host": host,
            "port": self._port.value(),
            "timeout": self._timeout.value(),
        }

    def _execute(self, inputs):
        from netrecon.tools.ssl_checker import check_ssl

        return check_ssl(
            inputs["host"], inputs["port"], inputs["timeout"]
        )

    def _format_result(self, r):
        if "error" in r:
            return f"Error: {r['error']}"

        lines = []
        fields = [
            ("Host", f"{r['host']}:{r['port']}"),
            ("Subject (CN)", r["subject_cn"]),
            ("Issuer", f"{r['issuer_cn']} ({r['issuer_org']})"),
            ("Valid From", r["not_before"]),
            ("Valid Until", r["not_after"]),
            ("Days Left", str(r.get("days_left", "N/A"))),
            ("TLS Version", r["version"]),
            ("Cipher", f"{r['cipher_name']} ({r['cipher_bits']}-bit)"),
        ]
        for label, val in fields:
            lines.append(f"{label:>16s}:  {val}")

        san = r.get("san", [])
        if san:
            lines.append(f"{'Alt Names':>16s}:  {', '.join(san[:8])}")
        return "\n".join(lines)


class TraceroutePanel(ToolPanel):
    tool_name = "traceroute"
    tool_label = "Traceroute"
    is_active = True

    def _build_inputs(self):
        self._target = QLineEdit()
        self._target.setPlaceholderText("example.com or 8.8.8.8")
        self._form.addRow("Destination:", self._target)

        self._max_hops = QSpinBox()
        self._max_hops.setRange(1, 64)
        self._max_hops.setValue(30)
        self._form.addRow("Max hops:", self._max_hops)

        self._timeout = QSpinBox()
        self._timeout.setRange(1, 10)
        self._timeout.setValue(3)
        self._timeout.setSuffix(" sec")
        self._form.addRow("Timeout:", self._timeout)

    def _collect_inputs(self):
        target = self._target.text().strip()
        if not target:
            raise ValueError("Enter a destination host.")
        return {
            "target": target,
            "max_hops": self._max_hops.value(),
            "timeout": self._timeout.value(),
        }

    def _execute(self, inputs):
        from netrecon.tools.traceroute import run_traceroute

        return run_traceroute(
            inputs["target"], inputs["max_hops"], inputs["timeout"]
        )

    def _format_result(self, hops):
        lines = [
            f"{'Hop':>4s}  {'Host':<28s}{'IP':<18s}RTT",
            "─" * 70,
        ]
        for h in hops:
            if h["host"] == "*":
                lines.append(f"{h['hop']:>4d}  {'* * *':<28s}")
            else:
                rtt = (
                    "  ".join(f"{r:.1f} ms" for r in h["rtts"])
                    if h["rtts"]
                    else "N/A"
                )
                lines.append(
                    f"{h['hop']:>4d}  {h['host']:<28s}"
                    f"{h['ip']:<18s}{rtt}"
                )
        lines.append("")
        lines.append(f"Trace complete: {len(hops)} hops")
        return "\n".join(lines)


class PcapViewerPanel(ToolPanel):
    tool_name = "pcap_viewer"
    tool_label = "PCAP Viewer"
    is_active = False

    def _build_inputs(self):
        row = QHBoxLayout()
        self._filepath = QLineEdit()
        self._filepath.setPlaceholderText("/path/to/capture.pcap")
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(self._filepath, stretch=1)
        row.addWidget(browse_btn)
        self._form.addRow("PCAP file:", row)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP file",
            "",
            "Packet Captures (*.pcap *.pcapng);;All Files (*)",
        )
        if path:
            self._filepath.setText(path)

    def _collect_inputs(self):
        fp = self._filepath.text().strip()
        if not fp:
            raise ValueError("Select a PCAP file.")
        return {"filepath": fp}

    def _execute(self, inputs):
        from netrecon.tools.pcap_viewer import read_pcap

        return read_pcap(inputs["filepath"])

    def _format_result(self, info):
        from netrecon.utils import get_service_info

        total = info["total_packets"]
        lines = [
            f"File: {info['filename']}   Packets: {total:,}",
            "",
            "── Protocol Distribution ──",
            f"{'Protocol':<14}{'Packets':>10}{'%':>8}",
            "─" * 32,
        ]
        for proto, count in info["protocols"].most_common():
            pct = count / total * 100 if total else 0
            lines.append(f"{proto:<14}{count:>10,}{pct:>7.1f}%")

        if info["top_src_ips"]:
            lines.append("")
            lines.append("── Top Source IPs ──")
            for ip, count in info["top_src_ips"][:5]:
                lines.append(f"  {ip:<20}{count:,} packets")

        if info["top_dst_ports"]:
            lines.append("")
            lines.append("── Top Destination Ports ──")
            for port, count in info["top_dst_ports"][:8]:
                svc, _ = get_service_info(port)
                label = (
                    f"{port} ({svc})" if svc != "Unknown" else str(port)
                )
                lines.append(f"  {label:<24}{count:,} packets")

        return "\n".join(lines)


class LogParserPanel(ToolPanel):
    tool_name = "log_parser"
    tool_label = "Log Parser"
    is_active = False

    def _build_inputs(self):
        row = QHBoxLayout()
        self._filepath = QLineEdit()
        self._filepath.setPlaceholderText("/path/to/auth.log")
        browse_btn = QPushButton("Browse…")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(self._filepath, stretch=1)
        row.addWidget(browse_btn)
        self._form.addRow("Log file:", row)

        self._log_type = QComboBox()
        self._log_type.addItems(["Auto-detect", "Auth", "HTTP"])
        self._form.addRow("Log type:", self._log_type)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select log file",
            "",
            "Log Files (*.log);;All Files (*)",
        )
        if path:
            self._filepath.setText(path)

    def _collect_inputs(self):
        fp = self._filepath.text().strip()
        if not fp:
            raise ValueError("Select a log file.")
        lt = self._log_type.currentText().lower().replace("-detect", "")
        return {"filepath": fp, "log_type": lt}

    def _execute(self, inputs):
        from netrecon.tools.log_parser import (
            detect_log_type,
            parse_auth_log,
            parse_http_log,
        )

        fp = inputs["filepath"]
        lt = inputs["log_type"]

        if lt == "auto":
            lt = detect_log_type(fp)
            if lt == "unknown":
                raise ValueError(
                    "Could not detect log type. "
                    "Select Auth or HTTP manually."
                )

        if lt == "auth":
            return parse_auth_log(fp)
        return parse_http_log(fp)

    def _format_result(self, info):
        lines = []
        if info["log_type"] == "auth":
            lines.append(f"Lines parsed:       {info['total_lines']:,}")
            lines.append(
                f"Failed logins:      {info['failed_logins']:,}"
            )
            lines.append(
                f"Successful logins:  {info['successful_logins']:,}"
            )

            bf = info.get("brute_force_ips", {})
            if bf:
                lines.append("")
                lines.append(
                    f"⚠  BRUTE-FORCE detected from {len(bf)} IP(s):"
                )
                for ip, count in sorted(
                    bf.items(), key=lambda x: -x[1]
                ):
                    lines.append(f"   {ip} — {count} failed attempts")

            if info["top_failed_ips"]:
                lines.append("")
                lines.append("── Top Failed Login Sources ──")
                for ip, count in info["top_failed_ips"]:
                    lines.append(f"  {ip:<20}{count} attempts")

            if info["top_failed_users"]:
                lines.append("")
                lines.append("── Most Targeted Usernames ──")
                for user, count in info["top_failed_users"]:
                    lines.append(f"  {user:<20}{count} attempts")
        else:
            lines.append(f"Total requests:  {info['total_requests']:,}")
            lines.append(f"Unique IPs:      {info['unique_ips']:,}")

            if info["status_codes"]:
                lines.append("")
                lines.append("── Status Codes ──")
                for code, count in info["status_codes"]:
                    lines.append(f"  {code}  {count:,}")

            sus = info.get("suspicious_requests", [])
            if sus:
                lines.append("")
                lines.append(
                    f"⚠  Suspicious requests: {len(sus)}"
                )
                for ip, path, status in sus[:10]:
                    lines.append(f"  {ip:<18}{path:<30}{status}")

        return "\n".join(lines)


# ── Panel registry ───────────────────────────────────────────

ALL_PANELS = [
    SubnetCalcPanel,
    PortScannerPanel,
    DnsLookupPanel,
    PingSweepPanel,
    BannerGrabPanel,
    WhoisPanel,
    HeaderInspectorPanel,
    SslCheckerPanel,
    TraceroutePanel,
    PcapViewerPanel,
    LogParserPanel,
]
