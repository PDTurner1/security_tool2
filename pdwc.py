# Patrick Turner
# CSC 842 - Tool #2
# Dr. Welu
# June 14, 2026


#	Pre Deployment workstation check (PDWC 1.0)
#
#	This program is designed to run on a pre-deployment of workstations into production
#	to test if Defender/antivirus, Windows firewall, and bitlocker are on and implemented
#	correctly.

import argparse					 # command line argument parsing
import datetime					 # time and date generation
import getpass					 # password promt (secure)
import json					 # json tools
import sys					 # sys exit for return codes
from abc import ABC, abstractmethod		 # abstract base support
from dataclasses import asdict, dataclass, field # results objects
from pathlib import Path			 # file path objects
from typing import Optional			 # type hints

# WinRM - usd to run Powershell commands on Windows over HTTP/HTTPS

try:
	import winrm				 # WinRM client
	from winrm.exceptions import WinRMError, WinRMTransportError
except ImportError:
	print("ERROR: pywinrm is not installed.\n  pip install pywinrm")
	sys.exit(1)

# Constants used for status codes

STATUS_PASS  = "PASS"
STATUS_WARN  = "WARN"
STATUS_FAIL  = "FAIL"
STATUS_ERROR = "ERROR"

# Check results data class

@dataclass
class CheckResult:
	name: str
	status: str           # PASS | WARN | FAIL | ERROR
	summary: str
	details: dict         = field(default_factory=dict)
	remediation: Optional[str] = None


# WinRM class - remote powershell execution wrapper

class WinRMSession:
	"""
	Thin wrapper around a pywinrm Protocol/Session.
	Passed into every check so it can run PowerShell remotely.
	"""

	def __init__(
		self,
		host: str,
		username: str,
		password: str,
		use_https: bool = False,	# True = 5986 (HTTPS), False = 5985 (HTTP)
		verify_ssl: bool = True,	# Set False to accept self-signed certs
		auth: str = "ntlm",		# ntlm authentication
		port: Optional[int] = None,	# Change default port
		timeout: int = 30,
	):
		self.host = host
				# Build url
		scheme       = "https" if use_https else "http"
		default_port = 5986 if use_https else 5985
		self.port    = port or default_port
		endpoint     = f"{scheme}://{host}:{self.port}/wsman"

		cert_validation = "ignore" if (use_https and not verify_ssl) else "validate"

		self._protocol = winrm.Protocol(
			endpoint=endpoint,
			transport=auth,
			username=username,
			password=password,
			server_cert_validation=cert_validation,
			operation_timeout_sec=timeout,
			read_timeout_sec=timeout + 10,
		)

	# Execute powershell script on the remote computer and returns stdout
	# Close shell when complete

	def run_ps(self, script: str) -> str:
		"""Execute a PowerShell script and return stdout. Raises on error."""
		import base64

		encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
		command = f"powershell -NonInteractive -NoProfile -EncodedCommand {encoded}"

		shell_id = self._protocol.open_shell()
		try:
			cmd_id = self._protocol.run_command(shell_id, command)
			stdout, stderr, rc = self._protocol.get_command_output(shell_id, cmd_id)
		finally:
			self._protocol.close_shell(shell_id)

			# decode byte output to strings
		out = stdout.decode("utf-8", errors="replace").strip()
		err = stderr.decode("utf-8", errors="replace").strip()
			# non-zero code as failure
		if rc != 0:
			raise RuntimeError(err or f"PowerShell exited with code {rc}")
		return out

	#return parsed (JSON) python object

	def run_ps_json(self, script: str) -> object:
		"""Run PowerShell that emits JSON; return parsed Python object."""
		raw = self.run_ps(script)
		return json.loads(raw)

# Base check class for all validation checks

class BaseCheck(ABC):
	name: str = "Unnamed Check"
	@abstractmethod
	def run(self, session: WinRMSession) -> CheckResult:
		...

# Check 1 – Windows Defender / Antivirus -------------------------------------------

class DefenderCheck(BaseCheck):
	name = "Windows Defender / Antivirus"
		# Number of days for signature check for warning and fail
	SIGNATURE_WARN_DAYS = 3
	SIGNATURE_FAIL_DAYS = 7
		# Gather MS defender properties
	def run(self, session: WinRMSession) -> CheckResult:
		ps = r"""
$mp = Get-MpComputerStatus | Select-Object `
	AMServiceEnabled, AntispywareEnabled, AntivirusEnabled,
	RealTimeProtectionEnabled, BehaviorMonitorEnabled,
	AntispywareSignatureLastUpdated, AntivirusSignatureLastUpdated,
	AntispywareSignatureVersion, AntivirusSignatureVersion,
	AMEngineVersion, AMProductVersion,
	QuickScanAge, FullScanAge
$mp | ConvertTo-Json -Depth 3
"""
		try:
			data = session.run_ps_json(ps)
		except Exception as exc:
			return CheckResult(
				name=self.name, status=STATUS_ERROR,
				summary=f"Unable to query Defender: {exc}",
				remediation="Ensure Windows Defender service is running and WinRM account has Administrator rights.",
			)
		# Gather all issues and warnings from defender into two lists
		issues, warns = [], []

		protection_flags = {
			"AM Service":           data.get("AMServiceEnabled"),
			"Antispyware":          data.get("AntispywareEnabled"),
			"Antivirus":            data.get("AntivirusEnabled"),
			"Real-Time Protection": data.get("RealTimeProtectionEnabled"),
			"Behavior Monitor":     data.get("BehaviorMonitorEnabled"),
		}
		for label, val in protection_flags.items():
			if val is False:
				issues.append(f"{label} is disabled")
			# Parse data returned
		sig_age_days = None
		raw_date = data.get("AntivirusSignatureLastUpdated") or data.get("AntispywareSignatureLastUpdated")
		if raw_date:
			try:
				if raw_date.startswith("/Date("):
					ms = int(raw_date[6:raw_date.index(")")])
					updated = datetime.datetime.fromtimestamp(
						ms / 1000, tz=datetime.timezone.utc)
				else:
					updated = datetime.datetime.fromisoformat(raw_date.replace("Z", "+00:00"))
				sig_age_days = (datetime.datetime.now(datetime.timezone.utc) - updated).days
			except Exception:
				pass
			# Determine ages
		if sig_age_days is not None:
			if sig_age_days >= self.SIGNATURE_FAIL_DAYS:
				issues.append(f"Signatures are {sig_age_days} day(s) old (fail threshold: {self.SIGNATURE_FAIL_DAYS})")
			elif sig_age_days >= self.SIGNATURE_WARN_DAYS:
				warns.append(f"Signatures are {sig_age_days} day(s) old (warn threshold: {self.SIGNATURE_WARN_DAYS})")

		quick_scan_age = data.get("QuickScanAge")
		if quick_scan_age is not None and quick_scan_age > 7:
			warns.append(f"Last quick scan was {quick_scan_age} day(s) ago")
			# Determine issues
		if issues:
			status, summary = STATUS_FAIL, f"Defender issues: {'; '.join(issues)}"
		elif warns:
			status, summary = STATUS_WARN, f"Defender warnings: {'; '.join(warns)}"
		else:
			status, summary = STATUS_PASS, "Windows Defender is active and signatures are current"
			# Return results
		return CheckResult(
			name=self.name, status=status, summary=summary,
			details={
				"protection_flags":     protection_flags,
				"signature_age_days":   sig_age_days,
				"av_signature_version": data.get("AntivirusSignatureVersion"),
				"engine_version":       data.get("AMEngineVersion"),
				"product_version":      data.get("AMProductVersion"),
				"quick_scan_age_days":  quick_scan_age,
				"full_scan_age_days":   data.get("FullScanAge"),
			},
			# Remediation suggestions
			remediation=(
				"Run 'Update-MpSignature' to refresh signatures. "
				"Enable disabled components via Windows Security or Group Policy."
			) if issues or warns else None,
		)


# Check 2 – Firewall Check ----------------------------------------------------------

class FirewallCheck(BaseCheck):
	name = "Windows Firewall Profiles"
			# Determines if firwall is enabled on Domain, Public, and Private
	def run(self, session: WinRMSession) -> CheckResult:
		ps = r"Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Depth 2"
		try:
			data = session.run_ps_json(ps)
		except Exception as exc:
			return CheckResult(
				name=self.name, status=STATUS_ERROR,
				summary=f"Unable to query firewall profiles: {exc}",
				remediation="Ensure Windows Firewall service is running and account has Administrator rights.",
			)

		if isinstance(data, dict):
			data = [data]

		profiles = {p["Name"]: bool(p["Enabled"]) for p in data}
		disabled = [n for n, en in profiles.items() if not en]
				# return result if disabled
		if disabled:
			return CheckResult(
				name=self.name, status=STATUS_FAIL,
				summary=f"Firewall profile(s) disabled: {', '.join(disabled)}",
				details={"profiles": profiles},
				remediation=(
					f"Set-NetFirewallProfile -Profile {','.join(disabled)} -Enabled True"
				),
			)
				# return result if enabled
		return CheckResult(
			name=self.name, status=STATUS_PASS,
			summary="All firewall profiles (Domain, Private, Public) are enabled",
			details={"profiles": profiles},
		)


# Check 3 – BitLocker ---------------------------------------------------------

class BitLockerCheck(BaseCheck):
	name = "BitLocker Drive Encryption"

	PROTECTED_STATUSES = {"FullyEncrypted", "EncryptionInProgress"}
		# gather data from computer
	def run(self, session: WinRMSession) -> CheckResult:
		ps = r"""
$vols = Get-BitLockerVolume | Select-Object `
	MountPoint, VolumeStatus, EncryptionPercentage,
	ProtectionStatus, LockStatus, EncryptionMethod, KeyProtector
$vols | ConvertTo-Json -Depth 4
"""
		try:
			data = session.run_ps_json(ps)
		except Exception as exc:
			return CheckResult(
				name=self.name, status=STATUS_ERROR,
				summary=f"Unable to query BitLocker: {exc}",
				remediation=(
					"Ensure BitLocker service is running. "
					"Requires Windows 10/11 Pro, Enterprise, or Education."
				),
			)

		if isinstance(data, dict):
			data = [data]
			# volume status by instance
		VOLUME_STATUS_MAP = {
		0: "FullyDecrypted",
		1: "FullyEncrypted",
		2: "EncryptionInProgress",
		3: "DecryptionInProgress",
		4: "EncryptionPaused",
		5: "DecryptionPaused",
				}
			# on/off status
		PROTECTION_STATUS_MAP = {
		0: "Off",
		1: "On",
		2: "Unknown",
				}
			# encryption methods
		ENCRYPTION_METHOD_MAP = {
		0: "None",
		1: "AES_128_WITH_DIFFUSER",
		2: "AES_256_WITH_DIFFUSER",
		3: "AES_128",
		4: "AES_256",
		5: "HARDWARE_ENCRYPTION",
		6: "XtsAes128",
		7: "XtsAes256",
				}
			# how bitlocker was implemented
		KEY_PROTECTOR_MAP = {
		0: "Unknown",
		1: "Tpm",
		2: "ExternalKey",
		3: "RecoveryPassword",
		4: "TpmPin",
		5: "TpmStartupKey",
		6: "TpmPinStartupKey",
		7: "PublicKey",
		8: "Password",
		9: "TpmNetworkKey",
		10: "AdAccountOrGroup",
				}
			# create lists for volumes and unprotected volumes
		volumes = []
		unprotected = []

		for vol in data:
			mp = vol.get("MountPoint", "?")
			enc_pct = vol.get("EncryptionPercentage", 0)

 
		vstatus = VOLUME_STATUS_MAP.get(vol.get("VolumeStatus", 0), str(vol.get("VolumeStatus")))
		pstatus = PROTECTION_STATUS_MAP.get(vol.get("ProtectionStatus", 0), str(vol.get("ProtectionStatus")))
		enc_method = ENCRYPTION_METHOD_MAP.get(vol.get("EncryptionMethod", 0), str(vol.get("EncryptionMethod")))

		kp_raw = vol.get("KeyProtector") or []
		if isinstance(kp_raw, dict):
			kp_raw = [kp_raw]
		protectors = [
		KEY_PROTECTOR_MAP.get(kp.get("KeyProtectorType", 0), str(kp.get("KeyProtectorType")))
		for kp in kp_raw
				]

		fully_enc = vstatus in self.PROTECTED_STATUSES
		protection_on = pstatus == "On"
		secure = fully_enc and protection_on

		volumes.append({
			"mount_point": mp,
			"volume_status": vstatus,
			"protection_status": pstatus,
			"protection_on": protection_on,
			"fully_encrypted": fully_enc,
			"encryption_pct": enc_pct,
			"encryption_method": enc_method,
			"key_protectors": protectors,
			"secure": secure,
				})

		if not secure:
			unprotected.append(
				f"{mp} (status={vstatus}, protection={pstatus}, {enc_pct}% encrypted)"
					)
		if unprotected:
			return CheckResult(
				name=self.name, status=STATUS_FAIL,
				summary=f"Drive(s) not fully encrypted: {'; '.join(unprotected)}",
				details={"volumes": volumes},
				remediation=(
					"If BitLocker is enabled but suspended, run: "
					"Resume-BitLocker -MountPoint '<drive>'\n"
					"If not yet enabled: "
					"Enable-BitLocker -MountPoint '<drive>' "
					"-EncryptionMethod XtsAes256 -TpmProtector"
				),
			)
		return CheckResult(
			name=self.name, status=STATUS_PASS,
			summary=f"All {len(volumes)} drive(s) are BitLocker-protected",
			details={"volumes": volumes},
		)


# CHECKS registry — append new BaseCheck instances here to extend services

CHECKS: list[BaseCheck] = [
	DefenderCheck(),
	FirewallCheck(),
	BitLockerCheck(),
	# Other checks go here ------> NewCheck(),
]


# Build reports

def build_report(host: str, results: list[CheckResult]) -> dict:
	priority = [STATUS_ERROR, STATUS_FAIL, STATUS_WARN, STATUS_PASS]
	overall  = STATUS_PASS
	for r in results:
		if priority.index(r.status) < priority.index(overall):
			overall = r.status
	return {
		"report": {
			"generated_at":   datetime.datetime.now().isoformat(),
			"target_host":    host,
			"overall_status": overall,
			"checks_run":     len(results),
			"pass":  sum(1 for r in results if r.status == STATUS_PASS),
			"warn":  sum(1 for r in results if r.status == STATUS_WARN),
			"fail":  sum(1 for r in results if r.status == STATUS_FAIL),
			"error": sum(1 for r in results if r.status == STATUS_ERROR),
		},
		"results": [asdict(r) for r in results],
	}

# print reports

def print_report(report: dict) -> None:
	C = {STATUS_PASS: "\033[92m", STATUS_WARN: "\033[93m",
		 STATUS_FAIL: "\033[91m", STATUS_ERROR: "\033[95m"}
	RST  = "\033[0m"
	BOLD = "\033[1m"
	meta = report["report"]
	oc   = C.get(meta["overall_status"], "")
	print(f"\n{BOLD}{'='*62}")
	print(f"  Windows Workstation Validation Report")
	print(f"  Target : {meta['target_host']}")
	print(f"  Time   : {meta['generated_at']}")
	print(f"  Overall: {oc}{meta['overall_status']}{RST}{BOLD}")
	print(f"{'='*62}{RST}\n")
	for r in report["results"]:
		c = C.get(r["status"], "")
		print(f"  {BOLD}{r['name']}{RST}")
		print(f"  Status : {c}{r['status']}{RST}")
		print(f"  Summary: {r['summary']}")
		if r.get("remediation"):
			print(f"  Fix    : {r['remediation']}")
		print()
	print(
		f"{BOLD}Totals — "
		f"PASS:{meta['pass']}  WARN:{meta['warn']}  "
		f"FAIL:{meta['fail']}  ERROR:{meta['error']}{RST}\n"
	)


# Host connector to run checks

def validate_host(
	host: str,
	username: str,
	password: str,
	checks_to_run: list[BaseCheck],
	use_https: bool,
	verify_ssl: bool,
	auth: str,
	port: Optional[int],
	timeout: int,
) -> dict:
	print(f"\n[→] Connecting to {host} …", flush=True)
	try:
		session = WinRMSession(
			host=host, username=username, password=password,
			use_https=use_https, verify_ssl=verify_ssl,
			auth=auth, port=port, timeout=timeout,
		)
		# test the connection before running checks
		session.run_ps("Write-Output 'ok'")
	except Exception as exc:
		error_result = CheckResult(
			name="WinRM Connection",
			status=STATUS_ERROR,
			summary=f"Could not connect to {host}: {exc}",
			remediation=(
				"Verify WinRM is enabled on the target "
				"(Enable-PSRemoting -Force) and the host/port is reachable."
			),
		)
		return build_report(host, [error_result])

	print(f"[✓] Connected. Running {len(checks_to_run)} check(s) …", flush=True)
	results = []
	for check in checks_to_run:
		print(f"    • {check.name} …", end=" ", flush=True)
		r = check.run(session)
		print(r.status)
		results.append(r)

	return build_report(host, results)


# Entry point / Main loop

def main():
	parser = argparse.ArgumentParser(
		description="Validate Windows workstations remotely via WinRM.",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=__doc__,
	)

	# Target selection
	target = parser.add_mutually_exclusive_group(required=True)
	target.add_argument("--host",       metavar="IP/HOSTNAME",
						help="Single target host")
	target.add_argument("--hosts-file", metavar="FILE",
						help="Text file with one host per line (# lines are comments)")

	# Credentials
	parser.add_argument("--user",     required=True, metavar="USERNAME",
						help="Windows username (e.g. Administrator or DOMAIN\\\\user)")
	parser.add_argument("--password", metavar="PASSWORD",
						help="Password (omit to be prompted securely)")

	# Transport
	parser.add_argument("--https",         action="store_true",
						help="Use HTTPS (port 5986) instead of HTTP (5985)")
	parser.add_argument("--no-verify-ssl", action="store_true",
						help="Skip SSL certificate verification (useful for self-signed certs)")
	parser.add_argument("--auth",    default="ntlm",
						choices=["ntlm", "basic", "kerberos", "credssp"],
						help="WinRM authentication method (default: ntlm)")
	parser.add_argument("--port",    type=int, default=None,
						help="Override WinRM port (default: 5985 HTTP / 5986 HTTPS)")
	parser.add_argument("--timeout", type=int, default=30,
						help="Per-operation timeout in seconds (default: 30)")

	# Check filtering
	parser.add_argument("--checks", nargs="+", metavar="NAME",
						help="Run only checks whose names contain these substrings (case-insensitive)")

	# Output
	parser.add_argument("--json",     metavar="FILE",
						help="Write JSON report to FILE (single-host mode)")
	parser.add_argument("--json-dir", metavar="DIR",
						help="Write one JSON report per host to this directory (multi-host mode)")

	args = parser.parse_args()

	# Resolve password
	password = args.password or getpass.getpass(f"Password for {args.user}: ")

	# Resolve host list
	if args.host:
		hosts = [args.host]
	else:
		p = Path(args.hosts_file)
		if not p.exists():
			print(f"ERROR: hosts file not found: {p}")
			sys.exit(1)
		hosts = [
			line.strip() for line in p.read_text().splitlines()
			if line.strip() and not line.strip().startswith("#")
		]
		if not hosts:
			print("ERROR: hosts file contains no valid entries.")
			sys.exit(1)

	# Resolve check list
	checks_to_run = CHECKS
	if args.checks:
		filters = [f.lower() for f in args.checks]
		checks_to_run = [c for c in CHECKS if any(f in c.name.lower() for f in filters)]
		if not checks_to_run:
			print(f"No checks matched filter(s): {args.checks}")
			sys.exit(1)

	# Output directory
	json_dir = None
	if args.json_dir:
		json_dir = Path(args.json_dir)
		json_dir.mkdir(parents=True, exist_ok=True)

	# Run
	all_reports = []
	worst_overall = STATUS_PASS
	priority = [STATUS_ERROR, STATUS_FAIL, STATUS_WARN, STATUS_PASS]

	for host in hosts:
		report = validate_host(
			host=host,
			username=args.user,
			password=password,
			checks_to_run=checks_to_run,
			use_https=args.https,
			verify_ssl=not args.no_verify_ssl,
			auth=args.auth,
			port=args.port,
			timeout=args.timeout,
		)
		print_report(report)
		all_reports.append(report)

		host_status = report["report"]["overall_status"]
		if priority.index(host_status) < priority.index(worst_overall):
			worst_overall = host_status

		# Per-host JSON
		if json_dir:
			safe_name = host.replace(".", "_").replace(":", "_")
			out_path = json_dir / f"{safe_name}.json"
			out_path.write_text(json.dumps(report, indent=2, default=str))
			print(f"  Report saved → {out_path}")
		elif args.json and len(hosts) == 1:
			Path(args.json).write_text(json.dumps(report, indent=2, default=str))
			print(f"  Report saved → {args.json}")

	# Multi-host summary
	if len(hosts) > 1:
		print(f"\n{'='*62}")
		print(f"  Multi-Host Summary  ({len(hosts)} hosts)")
		print(f"{'='*62}")
		for rep in all_reports:
			m = rep["report"]
			print(f"  {m['target_host']:<30} {m['overall_status']}")
		print()

	sys.exit(0 if worst_overall in (STATUS_PASS, STATUS_WARN) else 1)


if __name__ == "__main__":
	main()
