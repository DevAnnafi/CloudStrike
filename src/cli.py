import argparse
from scanners.aws import S3Scanner, IAMScanner as AWSIAMScanner, EC2MetaDataScanner
from scanners.azure import MetaDataProbe, StorageChecker, RBACAnalyzer
from scanners.gcp import BucketScanner, IAMScanner as GCPIAMScanner, MetaDataScanner
import subprocess
from core import CloudProvider, progress_context, ReportGenerator
from rich.console import Console
from rich.table import Table


def main():
    parser = argparse.ArgumentParser(
        description="CloudSecure - Multi-Cloud Security Scanner"
    )
    subparsers = parser.add_subparsers(dest='command')
    scan_parser = subparsers.add_parser('scan', help='Scan cloud infrastructure for vulnerabilities')
    scan_parser.add_argument('--aws', action='store_true')
    scan_parser.add_argument('--azure', action='store_true')
    scan_parser.add_argument('--gcp', action='store_true')
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
                console.print("[yellow]Scanning for IAM vulnerabilies...[/yellow]")
            iam_scanner = AWSIAMScanner(args.profile)
            findings = iam_scanner.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[green]Scanning for EC2 Instances...[/green]")
            ec2_scanner = EC2MetaDataScanner()
            findings = ec2_scanner.scan()
            all_findings.extend(findings)

        if args.azure or args.all:
            result = subprocess.run(['az', 'account', 'show', '--query', 'id', '-o', 'tsv'], 
                capture_output=True, text=True)
            subscription_id = result.stdout.strip()
            if args.verbose:
                console.print("[cyan]Scanning for MetaData vulnerabilities...[/cyan]")
            metadata = MetaDataProbe()
            findings = metadata.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[yellow]Scanning for StorageChecker vulnerabilities...[/yellow]")
            storage_checker = StorageChecker(subscription_id)
            findings = storage_checker.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[green]Scanning for RBAC vulnerabilities...[/green]")
            rbac = RBACAnalyzer(subscription_id)
            findings = rbac.scan()
            all_findings.extend(findings)

        if args.gcp or args.all:
            result = subprocess.run(['gcloud', 'config', 'get-value', 'project'], 
                capture_output=True, text=True)
            project_id = result.stdout.strip()
            if args.verbose:
                console.print("[cyan]Scanning for Bucket vulnerabilities...[/cyan]")
            bucket_scan = BucketScanner(project_id)
            findings = bucket_scan.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[yellow]Scanning for IAM vulnerabilities...[/yellow]")
            iam_scan = GCPIAMScanner(project_id)
            findings = iam_scan.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[green]Scanning for MetaData vulnerabilities...[/green]")
            metadata_scan = MetaDataScanner()
            findings = metadata_scan.scan()
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

        if ((args.aws and args.azure) or (args.aws and args.gcp) or (args.azure and args.gcp)) or args.all:
            cloud_provider = "Multi-Cloud"
        elif args.azure:
            cloud_provider = "Azure"
        elif args.gcp:
            cloud_provider = "GCP"
        else:
            cloud_provider = "AWS"

        report = ReportGenerator(all_findings, cloud_provider)
        report.save_json(args.output)
        print(f"Report saved to {args.output} with {len(all_findings)} findings")

    except KeyboardInterrupt:
        console.print("\n[yellow] Scan interrupted by user[/yellow]")
        return

if __name__ == "__main__":
    main()