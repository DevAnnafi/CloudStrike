import argparse
from scanners.aws import S3Scanner, IAMScanner as AWSIAMScanner, EC2MetaDataScanner
from scanners.azure import MetaDataProbe, StorageChecker, RBACAnalyzer
from scanners.gcp import BucketScanner, IAMScanner as GCPIAMScanner, MetaDataScanner
import subprocess
from core import CloudProvider, progress_context, ReportGenerator
from rich.console import Console
from rich.table import Table
from core.config import MultiAccountConfig


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
    scan_parser.add_argument('--config', type=str, help='Path to multi-account configuration file')
    scan_parser.add_argument('--environment', type=str, help='Environment to scan (production, staging, etc.)')
    args = parser.parse_args()
    if args.command == 'scan':
        run_scan(args)

def run_multi_account_scan(args, console):
    config = MultiAccountConfig(args.config)
    config.load()
    
    env_config = config.get_environment(args.environment)
    
    console.print(f"\n[bold cyan]Multi-Account Scan:[/bold cyan] {args.environment}")
    console.print("=" * 60)
    
    all_findings = []
    
    if 'aws' in env_config:
        console.print(f"\n[bold yellow]AWS Accounts:[/bold yellow] {len(env_config['aws'])}")
        for account in env_config['aws']:
            profile = account['profile']
            account_name = account.get('name', profile)
            
            if args.verbose:
                console.print(f"\n  Scanning: {account_name}")

            scanner = S3Scanner(profile, account_name)
            findings = scanner.scan_buckets()
            all_findings.extend(findings)

            iam_scanner = AWSIAMScanner(profile, account_name)
            findings = iam_scanner.scan()
            all_findings.extend(findings)

            ec2_scanner = EC2MetaDataScanner(profile, account_name)
            findings = ec2_scanner.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print(f"    → Found {len([f for f in all_findings if f.get('account_name') == account_name])} findings")
              
    if 'azure' in env_config:
        console.print(f"\n[bold blue]Azure Subscriptions:[/bold blue] {len(env_config['azure'])}")
        for account in env_config['azure']:
            subscription_id = account['subscription_id']
            account_name = account.get('name', subscription_id)
            
            if args.verbose:
                console.print(f"\n  Scanning: {account_name}")
            
            storage_checker = StorageChecker(subscription_id, account_name)
            findings = storage_checker.scan()
            all_findings.extend(findings)

            rbac = RBACAnalyzer(subscription_id, account_name)
            findings = rbac.scan()
            all_findings.extend(findings)

            metadata = MetaDataProbe(account_name)
            findings = metadata.scan()
            all_findings.extend(findings)
    
    if 'gcp' in env_config:
        console.print(f"\n[bold green]GCP Projects:[/bold green] {len(env_config['gcp'])}")
        for account in env_config['gcp']:
            project_id = account['project_id']
            account_name = account.get('name', project_id)
            
            if args.verbose:
                console.print(f"\n  Scanning: {account_name}")
            
            bucket_scan = BucketScanner(project_id, account_name)
            findings = bucket_scan.scan()
            all_findings.extend(findings)

            iam_scan = GCPIAMScanner(project_id, account_name)
            findings = iam_scan.scan()
            all_findings.extend(findings)

            metadata_scan = MetaDataScanner(account_name)
            findings = metadata_scan.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print(f"    → Found {len([f for f in all_findings if f.get('account_name') == account_name])} findings")

    
    # Generate report (same as v1)
    console.print("\n[bold]Scan Summary:[/bold]")
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

    cloud_provider = f"{args.environment} (Multi-Account)"

    report = ReportGenerator(all_findings, cloud_provider)
    report.save_json(args.output)
    print(f"Report saved to {args.output} with {len(all_findings)} findings")
    
    return all_findings

def run_scan(args):
    try:
        console = Console()
        all_findings = []

        if args.config and args.environment:
            return run_multi_account_scan( args, console)
        
        if args.aws or args.all:
            if args.verbose:
                console.print("[bold yellow]AWS[/bold yellow] [bright_white]→ Scanning S3 buckets...[/bright_white]")
            scanner = S3Scanner(args.profile)
            findings = scanner.scan_buckets()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[bold yellow]AWS[/bold yellow] [bright_white]→ Scanning IAM privileges...[/bright_white]")
            iam_scanner = AWSIAMScanner(args.profile)
            findings = iam_scanner.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[bold yellow]AWS[/bold yellow] [bright_white]→ Scanning EC2 metadata...[/bright_white]")
            ec2_scanner = EC2MetaDataScanner()
            findings = ec2_scanner.scan()
            all_findings.extend(findings)

        if args.azure or args.all:
            result = subprocess.run(['az', 'account', 'show', '--query', 'id', '-o', 'tsv'], 
                capture_output=True, text=True)
            subscription_id = result.stdout.strip()
            if args.verbose:
                console.print("[bold blue]Azure[/bold blue] [bright_white]→ Scanning blob storage...[/bright_white]")
            metadata = MetaDataProbe()
            findings = metadata.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[bold blue]Azure[/bold blue] [bright_white]→ Scanning storage containers...[/bright_white]")
            storage_checker = StorageChecker(subscription_id)
            findings = storage_checker.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[bold blue]Azure[/bold blue] [bright_white]→ Scanning RBAC roles...[/bright_white]")
            rbac = RBACAnalyzer(subscription_id)
            findings = rbac.scan()
            all_findings.extend(findings)

        if args.gcp or args.all:
            result = subprocess.run(['gcloud', 'config', 'get-value', 'project'], 
                capture_output=True, text=True)
            project_id = result.stdout.strip()
            if args.verbose:
                console.print("[bold green]GCP[/bold green] [bright_white]→ Scanning storage buckets...[/bright_white]")
            bucket_scan = BucketScanner(project_id)
            findings = bucket_scan.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[bold green]GCP[/bold green] [bright_white]→ Scanning IAM bindings...[/bright_white]")
            iam_scan = GCPIAMScanner(project_id)
            findings = iam_scan.scan()
            all_findings.extend(findings)

            if args.verbose:
                console.print("[bold green]GCP[/bold green] [bright_white]→ Scanning compute metadata...[/bright_white]")
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