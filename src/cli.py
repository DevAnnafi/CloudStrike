import argparse
from scanners.aws import S3Scanner, IAMScanner, EC2MetaDataScanner
from core import CloudProvider, progress_context, ReportGenerator
from rich.console import Console
from rich.table import Table


def main():
    parser = argparse.ArgumentParser(
        description="CloudStrike - Multi-Cloud Security Scanner"
    )
    subparsers = parser.add_subparsers(dest='command')
    scan_parser = subparsers.add_parser('scan', help='Scan cloud infrastructure for vulnerabilities')
    scan_parser.add_argument('--aws', action='store_true')
    scan_parser.add_argument('--output', required=True)
    scan_parser.add_argument('--format', choices=['json', 'html'], default='json')
    scan_parser.add_argument('--all', action='store_true')
    scan_parser.add_argument('--profile',type=str, help="AWS profile name")
    scan_parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    if args.command == 'scan':
        run_scan(args)

def run_scan(args):
    try:
        console = Console()
        all_findings = []
        if args.aws or args.all:
            if args.verbose:
                console.print("[cyan]Scanning S3 buckets...[/cyan]")
            scanner = S3Scanner(args.profile)
            findings = scanner.scan_buckets()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[yellow] Scanning for IAM vulnerabilies...[/yellow]")
            iam_scanner = IAMScanner(args.profile)
            findings = iam_scanner.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[green]Scanning for EC2 Instances...[/green]")
            ec2_scanner = EC2MetaDataScanner()
            findings = ec2_scanner.scan()
            all_findings.extend(findings)

        console.print("\n[bold] Scan Summary: [/bold]")
        critical = len([f for f in all_findings if f["severity"] == "critical"])
        high = len([f for f in all_findings if f["severity"] == "high"])
        medium = len([f for f in all_findings if f["severity"] == "medium"])
        low = len([f for f in all_findings if f["severity"] == "low"])
        table = Table(show_header=True, header_style="bright_green")
        table.add_column("Severity")
        table.add_column("Count")
        table.add_row("Total", str(len(all_findings)))
        table.add_row("Critical", str(critical))
        table.add_row("High", str(high))
        table.add_row("Medium", str(medium))
        table.add_row("Low", str(low))
    
        console.print(table)

        report = ReportGenerator(all_findings, "AWS")
        report.save_json(args.output)
        print(f"Report saved to {args.output} with {len(all_findings)} findings")

    except KeyboardInterrupt:
        console.print("\n[yellow] Scan interrupted by user[/yellow]")
        return

if __name__ == "__main__":
    main()