#!/usr/bin/env python3
"""
sosreport 압축 파일 AI 분석 및 보고서 생성 모듈
sosreport 압축 파일을 입력받아 압축 해제, 데이터 추출, AI 분석, HTML 보고서 생성을 한 번에 수행합니다.

사용법:
    # 기본 사용법 (sosreport 압축 파일을 입력)
    python3 ai_analyzer.py sosreport-archive.tar.xz --llm-url <URL> --model <MODEL> --api-token <TOKEN>
"""

import os
import sys
import json
import requests
import argparse
import time
import re
import tarfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List
import html # HTML 이스케이프를 위해 추가
import io
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
import tempfile
import subprocess # chattr 명령어 실행을 위해 추가

# --- 그래프 생성을 위한 라이브러리 ---
# "pip install matplotlib" 명령어로 설치 필요
try:
    import matplotlib
    matplotlib.use('Agg') # GUI 백엔드 없이 실행하기 위한 설정
    import matplotlib.pyplot as plt
    import matplotlib.font_manager as fm
    import matplotlib.ticker as mticker
except ImportError:
    matplotlib = None
    plt = None

class SosreportParser:
    """sosreport 압축 해제 후 디렉토리에서 데이터를 파싱하여 JSON 구조로 만듭니다."""
    def __init__(self, extract_path: str):
        self.extract_path = Path(extract_path)
        subdirs = [d for d in self.extract_path.iterdir() if d.is_dir()]
        self.base_path = subdirs[0] if len(subdirs) == 1 else self.extract_path
        print(f"sosreport 데이터 분석 경로: {self.base_path}")
        
        self.report_date = datetime.now() # Fallback
        date_found = False

        # 1. timedatectl 시도 (더 정확한 정보)
        timedatectl_content = self._read_file(['sos_commands/systemd/timedatectl'])
        if timedatectl_content != 'N/A':
            try:
                # 예: Local time: Mon 2025-09-01 15:04:00 KST
                match = re.search(r'Local time:.*?(\d{4}-\d{2}-\d{2})', timedatectl_content)
                if match:
                    self.report_date = datetime.strptime(match.group(1), '%Y-%m-%d')
                    print(f"✅ sosreport 수집일 감지 (timedatectl): {self.report_date.strftime('%Y-%m-%d')}")
                    date_found = True
                else:
                    raise ValueError("timedatectl에서 'Local time'을 찾을 수 없음")
            except Exception as e:
                print(f"⚠️ 경고: timedatectl 파싱 실패: {e}. 다른 파일을 시도합니다.")

        # 2. date 파일 시도 (timedatectl 실패 또는 파일 부재 시)
        if not date_found:
            date_content = self._read_file(['sos_commands/date/date', 'sos_commands/general/date', 'date'])
            if date_content != 'N/A':
                try:
                    # 예: Mon Sep 1 15:04:00 KST 2025
                    match = re.search(r'([A-Za-z]{3})\s+[A-Za-z]{3}\s+(\d{1,2})\s+[\d:]+\s+.*?(\d{4})', date_content)
                    if match:
                        month_abbr, day, year = match.groups()
                        month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                        month = month_map.get(month_abbr)
                        if month:
                            self.report_date = datetime(int(year), month, int(day))
                            print(f"✅ sosreport 수집일 감지 (date): {self.report_date.strftime('%Y-%m-%d')}")
                            date_found = True
                        else:
                            raise ValueError(f"알 수 없는 월 약어: {month_abbr}")
                    else:
                         raise ValueError("인식할 수 없는 날짜 형식")
                except Exception as e:
                    print(f"⚠️ 경고: date 파일({date_content}) 파싱 실패: {e}.")
        
        if not date_found:
            print("⚠️ 경고: 'date' 또는 'timedatectl' 파일을 찾거나 파싱할 수 없어 오늘 날짜 기준으로 sar 파일을 검색합니다.")
            self.report_date = datetime.now()

        self.report_day_str = self.report_date.strftime('%d')
        self.report_full_date_str = self.report_date.strftime('%Y%m%d')


    def _read_file(self, possible_paths: List[str], default: str = 'N/A') -> str:
        """
        여러 예상 경로 중 파일을 찾아 안전하게 읽어 내용을 반환합니다.
        """
        for file_path in possible_paths:
            full_path = self.base_path / file_path
            if full_path.exists():
                try:
                    return full_path.read_text(encoding='utf-8', errors='ignore').strip()
                except Exception as e:
                    print(f"경고: '{file_path}' 파일 읽기 오류: {e}")
                    return "파일 읽기 오류"
        return default
    
    def _parse_installed_packages(self) -> List[str]:
        """installed-rpms 파일에서 '패키지-버전-릴리즈' 전체 문자열을 파싱합니다."""
        rpm_content = self._read_file([
            'installed-rpms', 
            'sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_NAME_-_VERSION_-_RELEASE_._ARCH_INSTALLTIME_date_awk_-F_printf_-59s_s_n_1_2_sort_-V', 
            'sos_commands/rpm/sh_-c_rpm_--nodigest_-qa_--qf_-59_NVRA_INSTALLTIME_date_sort_-V'
        ])

        if rpm_content == 'N/A' or not rpm_content.strip():
            print("⚠️ 'installed-rpms' 파일을 찾을 수 없거나 내용이 비어 있습니다.")
            return []
        
        packages = []
        package_pattern = re.compile(r'^([a-zA-Z0-9_.+-]+-\d+.*)')
        for line in rpm_content.split('\n'):
            line = line.strip()
            if not line or line.startswith(('gpg-pubkey', 'warning:', 'error:')):
                continue
            
            match = package_pattern.match(line)
            if match:
                packages.append(match.group(1))
            else:
                parts = line.split()
                if len(parts) > 0:
                    packages.append(parts[0])

        unique_packages = sorted(list(set(packages)))
        print(f"✅ 설치된 패키지(버전 포함) 파싱 완료: {len(unique_packages)}개")
        return unique_packages

    def _parse_system_details(self) -> Dict[str, Any]:
        """xsos 스타일의 상세 시스템 정보를 파싱합니다."""
        details = {}
        details['hostname'] = self._read_file(['hostname', 'sos_commands/general/hostname', 'proc/sys/kernel/hostname'])
        details['os_version'] = self._read_file(['etc/redhat-release'])
        
        uname_content = self._read_file(['uname', 'sos_commands/kernel/uname_-a'])
        uname_line = uname_content.split('\n')[0]
        parts = uname_line.split()
        if len(parts) >= 3:
            details['kernel'] = parts[2]
        else:
            details['kernel'] = uname_line

        dmidecode_content = self._read_file(['dmidecode', 'sos_commands/hardware/dmidecode'])
        model_match = re.search(r'Product Name:\s*(.*)', dmidecode_content)
        details['system_model'] = model_match.group(1).strip() if model_match else 'N/A'
        lscpu_content = self._read_file(['lscpu', 'sos_commands/processor/lscpu'])
        cpu_model = re.search(r'Model name:\s+(.*)', lscpu_content)
        cpu_cores = re.search(r'^CPU\(s\):\s+(\d+)', lscpu_content, re.MULTILINE)
        details['cpu'] = f"{cpu_cores.group(1) if cpu_cores else 'N/A'} x {cpu_model.group(1).strip() if cpu_model else 'N/A'}"
        meminfo_content = self._read_file(['proc/meminfo'])
        mem_total = re.search(r'MemTotal:\s+(\d+)\s+kB', meminfo_content)
        details['memory'] = f"{int(mem_total.group(1)) / 1024 / 1024:.1f} GiB" if mem_total else 'N/A'
        
        uptime_content = self._read_file(['uptime', 'sos_commands/general/uptime', 'sos_commands/host/uptime'])
        uptime_match = re.search(r'up\s+(.*?),\s+\d+\s+user', uptime_content)
        if uptime_match:
            details['uptime'] = uptime_match.group(1).strip()
        else:
            uptime_match_simple = re.search(r'up\s+(.*)', uptime_content)
            if uptime_match_simple:
                 details['uptime'] = uptime_match_simple.group(1).split(',')[0].strip()
            else:
                 details['uptime'] = uptime_content

        last_boot_str = "N/A"
        proc_stat_content = self._read_file(['proc/stat'])
        btime_match = re.search(r'^btime\s+(\d+)', proc_stat_content, re.MULTILINE)
        if btime_match:
            try:
                epoch_time = int(btime_match.group(1))
                boot_datetime = datetime.fromtimestamp(epoch_time)
                timedatectl_content = self._read_file(['sos_commands/host/timedatectl_status'])
                tz_match = re.search(r'Time zone:\s+[\w/]+\s+\((.*?),', timedatectl_content)
                tz_abbr = tz_match.group(1) if tz_match else ""
                formatted_date = boot_datetime.strftime(f'%a %b %d %H:%M:%S {tz_abbr} %Y').strip()
                last_boot_str = f"{formatted_date} (epoch: {epoch_time})"
            except (ValueError, OSError) as e:
                print(f"경고: 부팅 시간(epoch) 변환 실패: {e}")
                last_boot_str = "Epoch 변환 오류"
        if last_boot_str == "N/A" or "오류" in last_boot_str:
             last_boot_str = self._read_file(['sos_commands/boot/who_-b', 'sos_commands/startup/who_-b']).replace('system boot', '').strip()
        details['last_boot'] = last_boot_str
        
        return details

    def _parse_storage(self) -> List[Dict[str, str]]:
        df_content = self._read_file(['df', 'sos_commands/filesys/df_-alPh'])
        filesystems = []
        for line in df_content.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[0].startswith('/'):
                filesystems.append({'filesystem': parts[0], 'size': parts[1], 'used': parts[2], 'avail': parts[3], 'use%': parts[4], 'mounted_on': parts[5]})
        return filesystems

    def _parse_process_stats(self) -> Dict[str, Any]:
        ps_content = self._read_file(['sos_commands/process/ps_auxwww', 'sos_commands/process/ps_auxwwwm', 'ps'])
        if ps_content == 'N/A':
            return {'total': 0, 'by_user': [], 'uninterruptible': [], 'zombie': [], 'top_cpu': [], 'top_mem': []}

        lines = ps_content.split('\n')
        header_found = False
        processes = []
        
        for line in lines:
            if re.match(r'USER\s+PID\s+%CPU', line):
                header_found = True
                continue
            if not header_found:
                continue

            parts = line.split(maxsplit=10)
            if len(parts) >= 11:
                try:
                    processes.append({
                        'user': parts[0], 'pid': parts[1], 'cpu%': float(parts[2]),
                        'mem%': float(parts[3]), 'vsz': int(parts[4]), 'rss': int(parts[5]),
                        'stat': parts[7], 'start': parts[8], 'time': parts[9], 'command': parts[10]
                    })
                except (ValueError, IndexError):
                    continue
        
        total_processes = len(processes)
        uninterruptible = [p for p in processes if 'D' in p['stat']]
        zombie = [p for p in processes if 'Z' in p['stat']]
        
        user_stats = {}
        for p in processes:
            user = p['user']
            if user not in user_stats:
                user_stats[user] = {'cpu%': 0.0, 'mem%': 0.0, 'rss': 0}
            user_stats[user]['cpu%'] += p['cpu%']
            user_stats[user]['mem%'] += p['mem%']
            user_stats[user]['rss'] += p['rss']
        
        top_users = sorted(user_stats.items(), key=lambda item: item[1]['cpu%'], reverse=True)[:5]
        
        formatted_top_users = []
        for user, stats in top_users:
            formatted_top_users.append({
                'user': user,
                'cpu%': f"{stats['cpu%']:.1f}%",
                'mem%': f"{stats['mem%']:.1f}%",
                'rss': f"{stats['rss'] / 1024 / 1024:.2f} GiB" if stats['rss'] > 1024*1024 else f"{stats['rss'] / 1024:.2f} MiB"
            })
        
        top_cpu = sorted(processes, key=lambda p: p['cpu%'], reverse=True)[:5]
        top_mem = sorted(processes, key=lambda p: p['rss'], reverse=True)[:5]

        print(f"✅ 프로세스 통계 파싱 완료: {total_processes}개 프로세스")
        return {
            'total': total_processes,
            'by_user': formatted_top_users,
            'uninterruptible': uninterruptible,
            'zombie': zombie,
            'top_cpu': top_cpu,
            'top_mem': top_mem
        }

    def _parse_failed_services(self) -> List[str]:
        systemctl_content = self._read_file(['sos_commands/systemd/systemctl_list-units_--all'])
        failed_services = []
        for line in systemctl_content.split('\n'):
            if 'failed' in line:
                parts = line.strip().split()
                if len(parts) >= 4:
                    failed_services.append(f"{parts[0]} - {' '.join(parts[1:4])}")
        return failed_services

    def _parse_ip4_details(self) -> List[Dict[str, str]]:
        ip_addr_content = self._read_file(['sos_commands/networking/ip_addr', 'sos_commands/networking/ip_-d_address'])
        if ip_addr_content == 'N/A': return []
        
        interfaces = []
        blocks = re.split(r'^\d+:\s+', ip_addr_content, flags=re.MULTILINE)
        if not blocks[0].strip():
            blocks.pop(0)

        for block in blocks:
            if not block.strip(): continue
            iface_data = {}
            
            name_match = re.match(r'([\w.-]+):', block)
            if not name_match: continue
            iface_data['iface'] = name_match.group(1)

            mtu_match = re.search(r'mtu\s+(\d+)', block)
            iface_data['mtu'] = mtu_match.group(1) if mtu_match else '-'
            
            state_match = re.search(r'state\s+(\w+)', block)
            iface_data['state'] = state_match.group(1).lower() if state_match else 'unknown'
            
            master_match = re.search(r'master\s+([\w.-]+)', block)
            iface_data['master'] = master_match.group(1) if master_match else '-'

            mac_match = re.search(r'link/\w+\s+([\da-fA-F:]+)', block)
            iface_data['mac'] = mac_match.group(1) if mac_match else '-'

            ip_match = re.search(r'inet\s+([\d.]+/\d+)', block)
            iface_data['ipv4'] = ip_match.group(1) if ip_match else '-'
            
            interfaces.append(iface_data)
            
        return interfaces

    def _parse_network_details(self) -> Dict[str, Any]:
        details = {'netdev': [], 'sockstat': [], 'bonding': [], 'ethtool': {}}

        netdev_content = self._read_file(['proc/net/dev'])
        for line in netdev_content.split('\n')[2:]:
            if ':' not in line: continue
            iface, stats = line.split(':', 1)
            iface = iface.strip()
            stat_values = stats.split()
            if len(stat_values) == 16:
                details['netdev'].append({
                    'iface': iface,
                    'rx_bytes': int(stat_values[0]), 'rx_packets': int(stat_values[1]), 'rx_errs': int(stat_values[2]), 'rx_drop': int(stat_values[3]),
                    'rx_fifo': int(stat_values[4]), 'rx_frame': int(stat_values[5]), 'rx_compressed': int(stat_values[6]), 'rx_multicast': int(stat_values[7]),
                    'tx_bytes': int(stat_values[8]), 'tx_packets': int(stat_values[9]), 'tx_errs': int(stat_values[10]), 'tx_drop': int(stat_values[11]),
                    'tx_fifo': int(stat_values[12]), 'tx_colls': int(stat_values[13]), 'tx_carrier': int(stat_values[14]), 'tx_compressed': int(stat_values[15])
                })

        details['sockstat'] = self._read_file(['proc/net/sockstat']).split('\n')

        bonding_dir = self.base_path / 'proc/net/bonding'
        if bonding_dir.is_dir():
            for bond_file in bonding_dir.iterdir():
                bond_content = bond_file.read_text(encoding='utf-8', errors='ignore')
                bond_info = {'device': bond_file.name}
                mode_match = re.search(r'Bonding Mode:\s*(.*)', bond_content)
                if mode_match: bond_info['mode'] = mode_match.group(1).strip()
                slaves = re.findall(r'Slave Interface:\s*(\w+)', bond_content)
                bond_info['slaves'] = slaves
                details['bonding'].append(bond_info)
        
        ethtool_dir = self.base_path / 'sos_commands/networking'
        if ethtool_dir.is_dir():
            all_ifaces = [dev['iface'] for dev in details['netdev']]
            for iface_name in all_ifaces:
                details['ethtool'][iface_name] = {}
                
                content = self._read_file([f'sos_commands/networking/ethtool_{iface_name}'])
                link_match = re.search(r'Link detected:\s*(yes|no)', content)
                speed_match = re.search(r'Speed:\s*(.*)', content)
                driver_match = re.search(r'driver:\s*(.*)', content)
                fw_match = re.search(r'firmware-version:\s*(.*)', content)
                
                details['ethtool'][iface_name]['link'] = link_match.group(1) if link_match else 'N/A'
                details['ethtool'][iface_name]['speed'] = speed_match.group(1).strip() if speed_match else 'N/A'
                details['ethtool'][iface_name]['driver'] = driver_match.group(1).strip() if driver_match else 'N/A'
                details['ethtool'][iface_name]['firmware'] = fw_match.group(1).strip() if fw_match else 'N/A'

                content_s = self._read_file([f'sos_commands/networking/ethtool_-S_{iface_name}'])
                errors = {}
                for line in content_s.split('\n'):
                    match = re.search(r'\s*(\w+.*):\s*(\d+)', line)
                    if match and int(match.group(2)) > 0:
                        errors[match.group(1).strip()] = match.group(2)
                if errors:
                    details['ethtool'][iface_name]['errors'] = errors
        
        return details

    def _parse_routing_table(self) -> List[Dict[str, str]]:
        routing_content = self._read_file(['sos_commands/networking/ip_route_show_table_all', 'sos_commands/networking/ip_route_show'])
        routes = []
        exclusion_keywords = ["broadcast", "local", "unreachable"]

        for line in routing_content.split('\n'):
            if not line.strip(): continue
            parts = line.split()
            
            if parts[0] in exclusion_keywords:
                continue

            route_info = {'destination': parts[0], 'gateway': '-', 'device': '-', 'source': '-'}
            
            try:
                if 'via' in parts:
                    route_info['gateway'] = parts[parts.index('via') + 1]
                if 'dev' in parts:
                    route_info['device'] = parts[parts.index('dev') + 1]
                if 'src' in parts:
                    route_info['source'] = parts[parts.index('src') + 1]
            except IndexError:
                continue

            if route_info['source'].startswith('127.'): continue
            if route_info['destination'].lower() != 'default' and route_info['source'] == '-': continue
            
            routes.append(route_info)
        return routes

    def _parse_sar_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        명시된 우선순위에 따라 sosreport 수집 당일의 텍스트 기반 sar 데이터를 찾아 파싱합니다.
        """
        print("sar 성능 데이터 파싱 중...")
        
        search_paths = [
            {'path': f'sos_commands/sar/sar{self.report_day_str}'},
            {'path': f'sos_commands/sar/sar{self.report_full_date_str}'},
            {'path': f'var/log/sa/sar{self.report_day_str}'},
            {'path': f'var/log/sa/sar{self.report_full_date_str}'},
        ]

        content = None
        chosen_path = None
        for candidate in search_paths:
            file_path = self.base_path / candidate['path']
            if file_path.exists():
                print(f"  -> sar 파일 발견: {candidate['path']}")
                content = file_path.read_text(encoding='utf-8', errors='ignore')
                chosen_path = candidate['path']
                if content.strip():
                    break
        
        if not content or not content.strip():
            print("  -> 일반 경로에서 sar 파일을 찾지 못했거나 비어있어, 종합 sar 데이터(sar -A)로 대체합니다.")
            content = self._read_file(['sos_commands/monitoring/sar_-A'])
            chosen_path = 'sos_commands/monitoring/sar_-A'
            if content == 'N/A' or not content.strip():
                print("❌ 분석할 수 있는 sar 데이터를 찾지 못했습니다.")
                return {'cpu': [], 'memory': [], 'network': [], 'disk': [], 'load': []}

        # --- 데이터 유무 진단 ---
        if 'IFACE' not in content:
            print("⚠️ 경고: sar 파일에 네트워크 통계(-n DEV) 섹션이 없습니다. 관련 데이터 수집 설정이 비활성화되었을 수 있습니다.")
        if 'CPU' not in content and '%user' not in content:
            print("⚠️ 경고: sar 파일에 CPU 통계(-u) 섹션이 없습니다.")
        if 'kbmemfree' not in content:
            print("⚠️ 경고: sar 파일에 메모리 통계(-r) 섹션이 없습니다.")

        performance_data = self._parse_sar_text_content(content)

        if any(v for v in performance_data.values() if v):
            num_cpu = len(performance_data.get('cpu', []))
            num_mem = len(performance_data.get('memory', []))
            num_net = len(set(d.get('timestamp') for d in performance_data.get('network', [])))
            num_disk = len(set(d.get('timestamp') for d in performance_data.get('disk', [])))
            num_load = len(performance_data.get('load', []))
            print(f"✅ sar 데이터 파싱 성공: {chosen_path} "
                  f"(CPU: {num_cpu}, Mem: {num_mem}, Net: {num_net}, Disk: {num_disk}, Load: {num_load})")
            return performance_data
        else:
            print(f"    - {chosen_path} 파일에서 유효한 성능 데이터를 추출하지 못했습니다.")
            return {'cpu': [], 'memory': [], 'network': [], 'disk': [], 'load': []}

    def _parse_sar_text_content(self, sar_content: str) -> Dict[str, List[Dict[str, Any]]]:
        """
        고도화된 sar 텍스트 파서. 데이터 블록을 명확히 인지하여 다양한 sar 출력 형식에 안정적으로 대응합니다.
        """
        print("  -> 고도화된 sar 파서 실행 중...")
        performance_data = {'cpu': [], 'memory': [], 'network': [], 'disk': [], 'load': []}
        lines = sar_content.strip().replace('\r\n', '\n').split('\n')
        
        header_map = {}
        current_section = None

        for line in lines:
            line = line.strip()

            if not line or line.startswith('Average:') or line.startswith('Linux'):
                header_map, current_section = {}, None
                continue

            ts_match = re.match(r'^(\d{2}:\d{2}:\d{2}(?:\s+AM|\s+PM)?)', line)
            if not ts_match:
                continue

            parts = re.split(r'\s+', line)
            
            # 타임스탬프와 AM/PM을 제외한 실제 컬럼명 찾기
            metric_cols_start_index = 1
            if len(parts) > 1 and parts[1] in ['AM', 'PM']:
                metric_cols_start_index = 2
            
            metric_cols = parts[metric_cols_start_index:]
            
            # 헤더인지 데이터인지 판별 (헤더는 문자로만 구성된 경향이 있음)
            is_header = any(col.isalpha() or '%' in col or '/' in col for col in metric_cols) and \
                        not any(re.match(r'^\d+[,.]\d+$', col) for col in metric_cols)

            if is_header:
                current_section = None
                # 섹션 결정
                if 'CPU' in metric_cols and ('%user' in metric_cols or '%usr' in metric_cols):
                    current_section = 'cpu'
                elif 'IFACE' in metric_cols:
                    current_section = 'net'
                elif 'kbmemfree' in metric_cols:
                    current_section = 'mem'
                elif 'DEV' in metric_cols and 'tps' in metric_cols:
                    current_section = 'disk'
                elif 'runq-sz' in metric_cols:
                    current_section = 'load'
                
                if current_section:
                    header_map = {}
                    for i, col_name in enumerate(metric_cols):
                        # Normalize common variations like %usr -> %user
                        if col_name == '%usr':
                            col_name = '%user'
                        normalized_name = col_name.replace('%', 'pct_').replace('/', '_s')
                        header_map[normalized_name] = i
                continue

            if not current_section or not header_map:
                continue
            
            timestamp = ts_match.group(1)
            data_values = metric_cols

            try:
                entry = {'timestamp': timestamp}
                for key, index in header_map.items():
                    if index < len(data_values):
                        entry[key] = data_values[index]

                if current_section == 'cpu':
                    is_all_row = ('CPU' in entry and entry['CPU'] == 'all') or \
                                 ('CPU' not in header_map and data_values[0] == 'all')

                    if is_all_row:
                        performance_data['cpu'].append({
                            'timestamp': timestamp,
                            'user': float(entry.get('pct_user', '0').replace(',', '.')),
                            'system': float(entry.get('pct_system', entry.get('pct_sys', '0')).replace(',', '.')),
                            'iowait': float(entry.get('pct_iowait', '0').replace(',', '.')),
                            'idle': float(entry.get('pct_idle', '0').replace(',', '.'))
                        })
                elif current_section == 'mem':
                    performance_data['memory'].append(entry)
                elif current_section == 'net' and entry.get('IFACE') != 'lo':
                    performance_data['network'].append(entry)
                elif current_section == 'disk':
                    performance_data['disk'].append(entry)
                elif current_section == 'load':
                    performance_data['load'].append({
                        'timestamp': timestamp,
                        'ldavg-1': float(entry.get('ldavg-1', '0').replace(',', '.')),
                        'ldavg-5': float(entry.get('ldavg-5', '0').replace(',', '.')),
                        'ldavg-15': float(entry.get('ldavg-15', '0').replace(',', '.'))
                    })
            except (ValueError, IndexError, KeyError) as e:
                print(f"  -> sar 데이터 라인 파싱 경고: {e} | 라인: '{line}'")
                continue
                
        return performance_data


    def _parse_log_messages(self) -> List[str]:
        log_content = self._read_file(['var/log/messages', 'var/log/syslog'])
        if log_content == 'N/A' or not log_content.strip():
            print("⚠️ 'var/log/messages' 파일을 찾을 수 없거나 내용이 비어 있습니다.")
            return []

        keywords = ['error', 'failed', 'critical', 'panic', 'segfault', 'out of memory', 'i/o error', 'hardware error', 'nmi', 'call trace']
        warning_keyword = 'warning'
        unique_logs = {}
        log_prefix_re = re.compile(r'^[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+[\w.-]+\s+[^:]+:\s+')
        
        lines = log_content.split('\n')
        print(f"총 {len(lines)}줄의 로그를 분석하여 핵심 메시지를 추출합니다...")

        for line in lines:
            line_lower = line.lower()
            if not any(keyword in line_lower for keyword in keywords) and warning_keyword not in line_lower:
                continue

            core_message = log_prefix_re.sub('', line) or line
            normalized_message = re.sub(r'\b(sda|sdb|sdc|nvme0n1)\d*\b', 'sdX', core_message)
            normalized_message = re.sub(r'\b\d{4,}\b', 'N', normalized_message)
            normalized_message = re.sub(r'0x[0-9a-fA-F]+', '0xADDR', normalized_message)
            normalized_message = re.sub(r'\[\s*\d+\.\d+\]', '', normalized_message).strip()

            if not normalized_message: continue

            if normalized_message not in unique_logs:
                unique_logs[normalized_message] = {'original_line': line, 'count': 0}
            unique_logs[normalized_message]['count'] += 1

        if not unique_logs:
            print("✅ 'var/log/messages'에서 심각한 오류나 경고가 발견되지 않았습니다.")
            return []

        sorted_logs = sorted(unique_logs.items(), key=lambda item: item[1]['count'], reverse=True)
        formatted_results = []
        for normalized, data in sorted_logs[:100]:
            count = data['count']
            original_line = data['original_line']
            timestamp_match = re.match(r'^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})', original_line)
            timestamp = timestamp_match.group(1) if timestamp_match else "Timestamp N/A"
            formatted_results.append(f"[{count}회] {timestamp} - {normalized}")
        
        print(f"✅ 'var/log/messages'에서 {len(formatted_results)}개의 고유한 문제성 로그 그룹을 추출했습니다.")
        return formatted_results

    def parse(self) -> Dict[str, Any]:
        """주요 sosreport 파일들을 파싱하여 딕셔너리로 반환합니다."""
        print("sosreport 데이터 파싱 시작...")
        system_info = self._parse_system_details()
        system_info['routing_table'] = self._parse_routing_table()

        data = {
            "system_info": system_info,
            "ip4_details": self._parse_ip4_details(),
            "network_details": self._parse_network_details(),
            "storage": self._parse_storage(),
            "process_stats": self._parse_process_stats(),
            "failed_services": self._parse_failed_services(),
            "performance_data": self._parse_sar_data(),
            "installed_packages": self._parse_installed_packages(),
            "log_messages": self._parse_log_messages(),
            "analysis_timestamp": datetime.now().isoformat()
        }
        print("✅ sosreport 데이터 파싱 완료.")
        return data

class AIAnalyzer:
    def __init__(self, llm_url: str, model_name: Optional[str] = None, 
                 endpoint_path: str = "/v1/chat/completions",
                 api_token: Optional[str] = None,
                 timeout: int = 300,
                 output_dir: str = 'output'):
        """AI 분석기 초기화"""
        match = re.search(r'https?://[^\s\)]+', llm_url)
        cleaned_url = match.group(0) if match else llm_url
        
        self.llm_url = cleaned_url.rstrip('/')
        self.model_name = model_name
        self.endpoint_path = endpoint_path
        self.completion_url = f"{self.llm_url}{self.endpoint_path}"
        self.api_token = api_token
        self.timeout = timeout
        self.session = requests.Session()
        self.output_dir = Path(output_dir)
        
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
        if self.api_token:
            headers['Authorization'] = f'Bearer {self.api_token}'
        self.session.headers.update(headers)
        
        self._setup_korean_font()


        print("AI 분석기 초기화 완료")
        print(f"LLM 기본 URL: {self.llm_url}")
        if self.model_name:
            print(f"사용 모델: {self.model_name}")

    def _setup_korean_font(self):
        """matplotlib에서 한글을 지원하기 위해 'Malgun Gothic'을 우선적으로 설정하고, 없을 경우 대체 폰트를 찾습니다."""
        if not plt:
            return

        # 우선적으로 'Malgun Gothic'을 시도
        font_name = 'Malgun Gothic'
        
        try:
            # findfont: 폰트가 없으면 ValueError 발생
            fm.findfont(font_name, fallback_to_default=False)
            plt.rc('font', family=font_name)
            print(f"✅ Matplotlib 그래프 폰트를 '{font_name}'으로 설정했습니다.")
        except ValueError:
            print(f"⚠️ '{font_name}' 폰트를 찾을 수 없습니다. 시스템에 맞는 다른 한글 폰트를 검색합니다.")
            
            # OS에 따라 대체 폰트 목록 정의
            if sys.platform == "win32":
                font_candidates = ["Malgun Gothic", "NanumGothic", "Dotum"]
            elif sys.platform == "darwin":
                font_candidates = ["AppleGothic", "NanumGothic"]
            else: # Linux, etc.
                font_candidates = ["NanumGothic", "UnDotum"]
            
            found_font = None
            for candidate in font_candidates:
                try:
                    fm.findfont(candidate, fallback_to_default=False)
                    found_font = candidate
                    break # 첫 번째로 찾은 폰트 사용
                except ValueError:
                    continue

            if found_font:
                plt.rc('font', family=found_font)
                print(f"✅ 대체 폰트 '{found_font}'으로 설정했습니다.")
            else:
                print("❌ 시스템에서 사용할 수 있는 한글 폰트를 찾지 못했습니다.")
                print("  -> 그래프의 한글이 깨질 수 있습니다. '맑은 고딕'이나 '나눔고딕'을 설치해주세요.")
                if sys.platform.startswith("linux"):
                    print("  -> (예: sudo apt-get install fonts-nanum*)")

        # 마이너스 기호가 깨지는 것을 방지
        plt.rc('axes', unicode_minus=False)


    def list_available_models(self):
        print(f"'{self.llm_url}' 서버에서 사용 가능한 모델 목록을 조회합니다...")
        models_url = f"{self.llm_url}/v1/models"
        try:
            response = self.session.get(models_url, timeout=20)
            if response.status_code != 200:
                print(f"❌ 모델 목록 조회 실패: HTTP {response.status_code}, 내용: {response.text[:200]}")
                return

            models_data = response.json()
            if 'data' in models_data and models_data['data']:
                print("\n--- 사용 가능한 모델 ---")
                for model in models_data['data']:
                    print(f"- {model.get('id')}")
                print("------------------------\n")
            else:
                print("❌ 응답에서 모델 목록을 찾을 수 없습니다.")
        except requests.exceptions.RequestException as e:
            print(f"❌ 모델 목록 조회 중 네트워크 오류 발생: {e}")

    def check_llm_service(self, max_retries: int = 3) -> bool:
        print("LLM 서비스 상태 확인 중...")
        for attempt in range(max_retries):
            try:
                response = self.session.get(self.llm_url, timeout=10)
                if response.status_code in [200, 404, 401, 403]:
                    print(f"✅ LLM 서비스 연결 성공 (시도 {attempt + 1}/{max_retries})")
                    return True
            except requests.exceptions.RequestException as e:
                print(f"연결 시도 {attempt + 1} 실패: {e}")
            if attempt < max_retries - 1:
                time.sleep(5)
        print("❌ 3번 시도 후에도 LLM 서비스에 연결할 수 없습니다")
        return False

    def test_llm_connection(self) -> bool:
        if not self.model_name:
            print("⚠️ 모델 이름이 지정되지 않아 연결 테스트를 건너뜁니다.")
            return False
        print("LLM 연결 테스트 중...")
        try:
            test_payload = {"model": self.model_name, "messages": [{"role": "user", "content": "Connection test. Reply with 'OK'."}], "max_tokens": 10}
            response = self.session.post(self.completion_url, json=test_payload, timeout=30)
            if response.status_code == 200:
                result = response.json()
                if 'choices' in result and result.get('choices'):
                    print(f"✅ 연결 테스트 성공: {result['choices'][0]['message']['content'].strip()}")
                    return True
            print(f"❌ 연결 테스트 실패: HTTP {response.status_code}, 내용: {response.text[:200]}")
            return False
        except Exception as e:
            print(f"❌ 연결 테스트 중 예외 발생: {e}")
            return False

    def perform_ai_analysis(self, prompt: str, is_news_request: bool = False) -> Any:
        print("AI 분석 시작...")
        max_retries = 3
        wait_time = 2  # Initial wait time in seconds

        for attempt in range(max_retries):
            try:
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": "You are a helpful assistant designed to output JSON."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 16384, 
                    "temperature": 0.1,
                }
                start_time = time.time()
                print(f"LLM API 호출 중... (시도 {attempt + 1}/{max_retries})")

                if is_news_request and attempt == 0:
                    llm_log_path = self.output_dir / "llm_security_news.log"
                    with open(llm_log_path, 'a', encoding='utf-8') as f:
                        f.write("\n\n--- NEW PROMPT FOR SECURITY NEWS ---\n")
                        f.write(prompt)
                        f.write("\n\n--- LLM RESPONSE ---\n")
                    print("\n--- LLM에게 보낸 보안 뉴스 프롬프트 ---")
                    print(prompt[:500] + "...")
                    print("-------------------------------------\n")

                response = self.session.post(self.completion_url, json=payload, timeout=self.timeout)
                print(f"API 응답 시간: {time.time() - start_time:.2f}초")

                if response.status_code == 200:
                    result = response.json()
                    if 'choices' not in result or not result['choices']:
                        raise ValueError(f"API 응답에 'choices' 키가 없거나 비어 있습니다. 응답: {result}")
                    
                    ai_response = result['choices'][0]['message']['content']
                    if is_news_request:
                        with open(llm_log_path, 'a', encoding='utf-8') as f:
                            f.write(ai_response)
                    return self._parse_ai_response_json_only(ai_response)

                if 500 <= response.status_code < 600:
                    error_message = f"API 서버 오류 (HTTP {response.status_code})"
                    print(f"⚠️ {error_message}. {wait_time}초 후 재시도합니다.")
                    time.sleep(wait_time)
                    wait_time *= 2
                    continue
                
                else:
                    raise ValueError(f"API 호출 실패 (재시도 불가): HTTP {response.status_code}, 내용: {response.text[:500]}")

            except (requests.exceptions.RequestException, ValueError) as e:
                print(f"⚠️ AI 분석 중 오류 발생 (시도 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(wait_time)
                    wait_time *= 2
                else:
                    raise Exception(f"AI 분석 중 최종 오류 발생: {e}")

    def create_analysis_prompt(self, sosreport_data: Dict[str, Any]) -> str:
        print("AI 분석 프롬프트 생성 중...")
        
        log_summary = sosreport_data.get("log_messages", [])
        
        data_to_send = {
            "system_info": sosreport_data.get("system_info"),
            "storage": sosreport_data.get("storage"),
            "failed_services": sosreport_data.get("failed_services"),
            "process_stats_summary": {
                "total": sosreport_data.get("process_stats", {}).get("total"),
                "zombie_count": len(sosreport_data.get("process_stats", {}).get("zombie", [])),
            },
            "recent_log_warnings_and_errors": log_summary
        }

        data_str = json.dumps(data_to_send, indent=2, ensure_ascii=False)

        prompt = f"""당신은 Red Hat Enterprise Linux 시스템 전문가입니다. 다음 sosreport 분석 데이터와 시스템 로그를 종합적으로 검토하고 **한국어로** 전문적인 진단을 제공해주세요.

## 분석 데이터
```json
{data_str}
```

## 분석 가이드라인
- **심각한 이슈(critical_issues) 판단 기준**: 로그 내용에 'panic', 'segfault', 'out of memory', 'hardware error', 'i/o error', 'call trace'와 같은 명백한 시스템 장애나 데이터 손상 가능성을 암시하는 키워드가 포함된 경우, **반드시 '심각한 이슈'로 분류**해야 합니다.
- **경고(warnings) 판단 기준**: 당장 시스템 장애를 일으키지는 않지만, 잠재적인 문제로 발전할 수 있거나 주의가 필요한 로그(예: 'warning', 'failed' 등)는 '경고'로 분류합니다.

## 분석 절차 (내부적으로만 수행)
1.  **예비 분석**: 주어진 모든 데이터를 검토하고, 특히 `recent_log_warnings_and_errors` 목록에서 'panic', 'i/o error' 등 심각도를 나타내는 키워드를 식별하여 잠재적 이슈의 우선순위를 정합니다.
2.  **JSON 초안 작성 (내부적)**: 1단계 분석을 바탕으로, `critical_issues`, `warnings`, `recommendations` 항목을 채운 JSON 구조의 초안을 마음속으로 구성합니다. 이때, 각 권장사항(`recommendations`)이 어떤 로그(`related_logs`)에 근거하는지 명확히 연결합니다.
3.  **최종 JSON 검토 및 출력**: 2단계에서 구성한 초안을 최종적으로 검토하고, 빠진 내용이나 불일치는 없는지 확인한 후, 완전한 JSON 객체 **하나만을** 출력합니다.

## 최종 출력 형식
**모든 `critical_issues`, `warnings`, `recommendations`, `summary` 필드의 내용은 반드시 자연스러운 한국어로 작성해주세요.**

```json
{{
  "system_status": "정상|주의|위험",
  "overall_health_score": 100,
  "critical_issues": ["분석 가이드라인에 따라 식별된 심각한 문제들의 구체적인 설명"],
  "warnings": ["주의가 필요한 사항들"],
  "recommendations": [
    {{
      "priority": "높음|중간|낮음",
      "category": "성능|보안|안정성|유지보수",
      "issue": "문제점 설명",
      "solution": "구체적인 해결 방안",
      "related_logs": ["이 권장사항의 근거가 된 특정 로그 메시지(들)"]
    }}
  ],
  "summary": "전체적인 시스템 상태와 주요 권장사항에 대한 종합 요약"
}}
```

**중요**: 위 분석 절차에 따라 분석을 완료하고, 당신의 전체 응답은 오직 위 형식의 단일 JSON 객체여야 합니다. `related_logs` 필드는 근거가 된 로그가 없을 경우 빈 배열 `[]`로 출력해주세요. JSON 객체 앞뒤로 어떠한 설명, 요약, 추론 과정도 포함하지 마십시오.
"""
        return prompt

    def _parse_ai_response_json_only(self, ai_response: str) -> Any:
        print("AI 응답 파싱 중...")
        
        if not ai_response or not ai_response.strip():
            raise ValueError("AI 응답이 비어 있습니다.")

        refusal_patterns = ["i'm sorry", "i cannot", "i can't", "i am unable", "죄송합니다", "할 수 없습니다"]
        if any(pattern in ai_response.lower() for pattern in refusal_patterns):
            raise ValueError(f"LLM이 요청 처리를 거부했습니다. (응답: '{ai_response.strip()}')")

        try:
            cleaned_response = re.sub(r'^```(json)?\s*|\s*```$', '', ai_response.strip())
            return json.loads(cleaned_response)
        except json.JSONDecodeError as e:
            error_message = f"AI 응답 JSON 파싱 실패: {e}.\n--- 원본 응답 ---\n{ai_response}\n----------------"
            print(error_message)
            raise ValueError(error_message)
        except Exception as e:
            error_message = f"AI 응답 처리 중 예측하지 못한 오류 발생: {e}.\n--- 원본 응답 ---\n{ai_response}\n----------------"
            print(error_message)
            raise ValueError(error_message)

    def fetch_security_news(self, sos_data: Dict[str, Any]) -> List[Dict[str, str]]:
        print("최신 RHEL 보안 뉴스 조회 및 분석 시작...")
        
        installed_packages_full = sos_data.get("installed_packages", [])
        if not installed_packages_full:
            reason = "sosreport에 설치된 패키지 정보(installed-rpms)가 없어 CVE 연관성을 분석할 수 없습니다."
            print(f"⚠️ {reason}")
            return [{"reason": reason}]

        try:
            installed_packages_map = {re.sub(r'-[\d.:].*', '', pkg): pkg for pkg in installed_packages_full}
            installed_package_names_only = set(installed_packages_map.keys())
            kernel_version = sos_data.get("system_info", {}).get("kernel", "N/A")

            print(f"분석 대상 시스템 커널 버전: {kernel_version}")
            print(f"분석 대상 시스템의 설치된 패키지 {len(installed_packages_full)}개를 DB화하여 참고합니다.")

            api_url_raw = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
            
            match = re.search(r'https?://[^\s\)]+', api_url_raw)
            if not match:
                raise ValueError(f"Could not extract a valid URL from: {api_url_raw}")
            api_url = match.group(0)

            print(f"Red Hat CVE API 호출: {api_url}")
            response = requests.get(api_url, timeout=120)
            if response.status_code != 200:
                print(f"⚠️ Red Hat CVE API 조회 실패 (HTTP {response.status_code})")
                return [{"reason": f"Red Hat CVE API 조회에 실패했습니다 (HTTP {response.status_code})."}]

            all_cves = response.json()
            print(f"총 {len(all_cves)}개의 CVE 데이터를 Red Hat에서 가져왔습니다.")
            
            now = datetime.now()
            start_date = now - timedelta(days=365)
            
            system_relevant_cves = []
            added_cve_ids = set()
            severity_order = {"critical": 2, "important": 1, "moderate": 0, "low": -1}

            for cve in all_cves:
                cve_id = cve.get('CVE')
                public_date_str = cve.get('public_date')

                if not all([cve_id, public_date_str]) or cve_id in added_cve_ids:
                    continue
                
                try:
                    cve_date_str_no_ms = public_date_str.split('.')[0].replace('Z', '')
                    cve_date = datetime.strptime(cve_date_str_no_ms, '%Y-%m-%dT%H:%M:%S')
                except ValueError:
                    continue
                
                severity_value = cve.get('severity')
                severity = severity_value.lower() if isinstance(severity_value, str) else 'low'

                if not (start_date <= cve_date <= now and severity in ["critical", "important"]):
                    continue
                
                is_relevant = False
                matched_package_full_name = "N/A"
                for pkg_str in cve.get('affected_packages', []):
                    pkg_name_match = re.match(r'^([a-zA-Z0-9_.+-]+)-', pkg_str)
                    if pkg_name_match:
                        pkg_name = pkg_name_match.group(1)
                        if pkg_name in installed_package_names_only:
                            is_relevant = True
                            matched_package_full_name = installed_packages_map.get(pkg_name, "N/A")
                            break
                
                if is_relevant:
                    cve['matched_package'] = matched_package_full_name
                    system_relevant_cves.append(cve)
                    added_cve_ids.add(cve_id)

            print(f"시스템에 영향을 주는 CVE를 총 {len(system_relevant_cves)}개 발견했습니다.")
            system_relevant_cves.sort(key=lambda x: (severity_order.get(x.get('severity', 'low').lower(), -1), x.get('public_date')), reverse=True)
            
            # --- CVE 선정 로직: 패키지당 1개, 최대 5개 ---
            final_report_cves = []
            selected_packages = set()
            MAX_CVES_TO_REPORT = 20

            for cve in system_relevant_cves:
                if len(final_report_cves) >= MAX_CVES_TO_REPORT:
                    break

                pkg_full_name = cve.get('matched_package', '')
                if not pkg_full_name: continue
                
                pkg_name_match = re.match(r'^([a-zA-Z0-9_.+-]+)-', pkg_full_name)
                if not pkg_name_match: continue
                
                pkg_base_name = pkg_name_match.group(1)

                if pkg_base_name not in selected_packages:
                    final_report_cves.append(cve)
                    selected_packages.add(pkg_base_name)

            print(f"시스템 관련 CVE {len(final_report_cves)}개를 1차 선별했습니다. (패키지당 1개, 최대 {MAX_CVES_TO_REPORT}개)")

            if not final_report_cves:
                reason = "시스템에 설치된 패키지에 직접적인 영향을 주는 최신 보안 뉴스가 없습니다."
                print(reason)
                return [{"reason": reason}]

            processing_data = [{"cve_id": cve['CVE'], "description": cve.get('bugzilla_description', '요약 정보 없음')} for cve in final_report_cves]

            processing_prompt = f"""
[시스템 안내]
당신은 Red Hat Enterprise Linux(RHEL) 보안 전문가입니다. 당신의 임무는 주어진 각 CVE의 영문 기술 설명을 분석하여, 시스템 관리자가 쉽게 이해할 수 있도록 핵심 내용과 시스템에 미치는 영향을 중심으로 자연스러운 한국어로 요약 및 설명하는 것입니다.

[입력 데이터]
```json
{json.dumps(processing_data, indent=2, ensure_ascii=False)}
```

[출력 지시]
아래 JSON 형식에 맞춰, 각 CVE에 대한 알기 쉬운 요약 설명을 포함하여 출력하십시오.
**중요**: 당신의 응답은 반드시 아래 JSON 형식의 객체여야 합니다. 어떠한 설명이나 추가 텍스트도 포함하지 마십시오.

```json
{{
  "processed_cves": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "translated_description": "해당 CVE의 핵심 위협과 시스템에 미치는 영향에 대한 쉽고 명확한 한국어 요약 설명"
    }}
  ]
}}
```
"""

            processed_result = self.perform_ai_analysis(processing_prompt, is_news_request=True)

            final_cves_with_translation = []
            if isinstance(processed_result, dict) and 'processed_cves' in processed_result:
                processed_map = {item['cve_id']: item for item in processed_result['processed_cves']}
                for cve_data in final_report_cves:
                    cve_id = cve_data['CVE']
                    if cve_id in processed_map:
                        processed_info = processed_map[cve_id]
                        cve_date_str = cve_data.get('public_date', '')
                        if cve_date_str:
                            try:
                                cve_date_str_no_ms = cve_date_str.split('.')[0].replace('Z', '')
                                cve_data['public_date'] = datetime.strptime(cve_date_str_no_ms, '%Y-%m-%dT%H:%M:%S').strftime('%y/%m/%d')
                            except ValueError: pass
                        
                        cve_data['bugzilla_description'] = processed_info.get('translated_description', cve_data['bugzilla_description'])
                        final_cves_with_translation.append(cve_data)
                        print(f"✅ 보안 뉴스 처리 완료: {cve_id}")
            else:
                print("⚠️ LLM의 번역 처리에 실패했습니다. 원본 데이터로 보고서를 생성합니다.")
                final_cves_with_translation = final_report_cves

            print("✅ 보안 뉴스 조회 및 처리 완료.")
            return final_cves_with_translation

        except Exception as e:
            print(f"❌ 보안 뉴스 조회 중 심각한 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            return [{"reason": f"보안 뉴스 조회 중 오류가 발생했습니다: {e}"}]

    def create_performance_graphs(self, sos_data: Dict[str, Any]) -> Dict[str, str]:
        """성능 데이터를 바탕으로 CPU, Memory, Network, Disk I/O, Load Average 그래프를 생성합니다."""
        if not plt:
            print("⚠️ 그래프 생성을 건너뜁니다. 'matplotlib' 라이브러리를 설치하세요.")
            return {}

        print("성능 그래프 생성 중...")
        graphs = {}
        plt.style.use('seaborn-whitegrid')

        perf_data = sos_data.get("performance_data", {})
        ip4_details = sos_data.get("ip4_details", [])
        interface_states = {iface.get('iface'): iface.get('state', 'unknown').upper() for iface in ip4_details}

        graph_style = {
            'figsize': (12, 6), 'title_fontsize': 16, 'label_fontsize': 12,
            'tick_rotation': 30, 'alpha': 0.7
        }
        
        # --- CPU 그래프 ---
        if perf_data.get('cpu') and len(perf_data['cpu']) > 1:
            try:
                # CPU 데이터는 파서에서 이미 float으로 변환됨
                cpu_data, timestamps = perf_data['cpu'], [d['timestamp'] for d in perf_data['cpu']]
                user, system, iowait = [d['user'] for d in cpu_data], [d['system'] for d in cpu_data], [d['iowait'] for d in cpu_data]
                
                fig, ax = plt.subplots(figsize=graph_style['figsize'])
                ax.stackplot(timestamps, user, system, iowait, 
                             labels=['User %', 'System %', 'I/O Wait %'], 
                             colors=['#4C72B0', '#DD8452', '#C44E52'], alpha=0.7)
                
                ax.set_title('CPU Usage (%)', fontsize=graph_style['title_fontsize'], weight='bold')
                ax.set_ylabel('Usage (%)', fontsize=graph_style['label_fontsize'])
                ax.legend(loc='upper left', frameon=True)
                ax.set_ylim(0, 100)
                ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                plt.tight_layout()
                
                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=100)
                graphs['cpu_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
                print("  - CPU 그래프 생성 완료")
            except Exception as e:
                print(f"  - ⚠️ CPU 그래프 생성 실패: {e}")

        # --- 메모리(RAM) 상세 그래프 ---
        if perf_data.get('memory') and len(perf_data['memory']) > 1:
            try:
                mem_data = perf_data['memory']
                timestamps = [d['timestamp'] for d in mem_data]

                def get_float_data(key):
                    values = []
                    for d in mem_data:
                        try:
                            value_str = d.get(key, '0.0')
                            values.append(float(value_str.replace(',', '.')))
                        except (ValueError, TypeError):
                            values.append(0.0)
                    return values

                kb_metrics = {
                    'kbmemfree': get_float_data('kbmemfree'),
                    'kbmemused': get_float_data('kbmemused'),
                    'kbbuffers': get_float_data('kbbuffers'),
                    'kbcached': get_float_data('kbcached'),
                    'kbcommit': get_float_data('kbcommit'),
                    'kbactive': get_float_data('kbactive'),
                    'kbinact': get_float_data('kbinact'),
                    'kbdirty': get_float_data('kbdirty')
                }
                
                fig, ax = plt.subplots(figsize=graph_style['figsize'])
                
                for key, values in kb_metrics.items():
                    ax.plot(timestamps, values, label=key, lw=2)
                
                ax.set_title('Memory Usage (KB)', fontsize=graph_style['title_fontsize'], weight='bold')
                ax.set_ylabel('Kilobytes', fontsize=graph_style['label_fontsize'])
                ax.legend(loc='upper left', frameon=True, fontsize='small', ncol=2)
                ax.grid(True)

                ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                
                plt.tight_layout()

                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=100)
                graphs['memory_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
                print("  - 메모리 통합 라인 그래프 생성 완료")
            except Exception as e:
                print(f"  - ⚠️ 메모리 그래프 생성 실패: {e}")

        # --- 네트워크 그래프 (개선된 로직) ---
        if perf_data.get('network') and len(perf_data['network']) > 1:
            network_by_iface = {}
            for d in perf_data['network']:
                iface = d.get('IFACE')
                if not iface: continue
                if iface not in network_by_iface: network_by_iface[iface] = []
                network_by_iface[iface].append(d)
            
            print(f"  -> sar 데이터에서 {len(network_by_iface)}개의 네트워크 인터페이스 발견: {', '.join(network_by_iface.keys())}")
            
            network_graphs_generated = False
            inactive_up_interfaces = []

            for iface, data in network_by_iface.items():
                state = interface_states.get(iface, 'UNKNOWN')
                if state != 'UP':
                    print(f"  - {iface} 인터페이스는 'State: UP' 상태가 아니므로 그래프를 건너뜁니다. (상태: {state})")
                    continue

                if len(data) < 2:
                    print(f"  - {iface} 인터페이스는 데이터 포인트가 부족하여 그래프를 건너뜁니다.")
                    continue
                
                try:
                    timestamps = [d['timestamp'] for d in data]
                    
                    def get_flexible_net_data(d_list, key_patterns):
                        values = []
                        if not d_list: return []
                        
                        first_item_keys = d_list[0].keys()
                        actual_key = None
                        
                        for pattern in key_patterns:
                            normalized_pattern = pattern.replace('/', '_s')
                            if normalized_pattern in first_item_keys:
                                actual_key = normalized_pattern
                                break
                        
                        if not actual_key: 
                            return [0.0] * len(d_list)

                        for d in d_list:
                            try:
                                value_str = d.get(actual_key, '0.0')
                                values.append(float(value_str.replace(',', '.')))
                            except (ValueError, TypeError):
                                values.append(0.0)
                        return values

                    rxpck = get_flexible_net_data(data, ['rxpck/s', 'rxpck_s'])
                    txpck = get_flexible_net_data(data, ['txpck/s', 'txpck_s'])
                    rxkB = get_flexible_net_data(data, ['rxkB/s', 'rxkB_s'])
                    txkB = get_flexible_net_data(data, ['txkB/s', 'txkB_s'])
                    rxcmp = get_flexible_net_data(data, ['rxcmp/s', 'rxcmp_s'])
                    txcmp = get_flexible_net_data(data, ['txcmp/s', 'txcmp_s'])
                    rxmcst = get_flexible_net_data(data, ['rxmcst/s', 'rxmcst_s'])

                    total_traffic = sum(rxpck) + sum(txpck) + sum(rxkB) + sum(txkB)
                    if total_traffic == 0.0:
                        print(f"  - {iface} 인터페이스는 트래픽이 없어 그래프 생성을 건너뜁니다.")
                        inactive_up_interfaces.append(iface)
                        continue

                    fig, ax1 = plt.subplots(figsize=(12, 6))
                    ax2 = ax1.twinx()
                    
                    ax1.plot(timestamps, rxpck, label='rxpck/s', color='tab:blue', linestyle='-')
                    ax1.plot(timestamps, txpck, label='txpck/s', color='tab:cyan', linestyle='-')
                    ax1.plot(timestamps, rxcmp, label='rxcmp/s', color='tab:green', linestyle=':')
                    ax1.plot(timestamps, txcmp, label='limegreen', linestyle=':')
                    ax1.plot(timestamps, rxmcst, label='rxmcst/s', color='tab:gray', linestyle='--')
                    ax1.set_ylabel('Packets/s', color='tab:blue', fontsize=graph_style['label_fontsize'])
                    ax1.tick_params(axis='y', labelcolor='tab:blue')

                    ax2.plot(timestamps, rxkB, label='rxkB/s', color='tab:red', linestyle='-')
                    ax2.plot(timestamps, txkB, label='txkB/s', color='tab:orange', linestyle='-')
                    ax2.set_ylabel('kB/s', color='tab:red', fontsize=graph_style['label_fontsize'])
                    ax2.tick_params(axis='y', labelcolor='tab:red')

                    ax1.set_title(f'Network Traffic: {iface} (State: {state})', fontsize=graph_style['title_fontsize'], weight='bold')
                    ax1.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                    plt.setp(ax1.get_xticklabels(), rotation=graph_style['tick_rotation'], ha='right')

                    lines1, labels1 = ax1.get_legend_handles_labels()
                    lines2, labels2 = ax2.get_legend_handles_labels()
                    ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left', frameon=True, ncol=2, fontsize='small')
                    plt.tight_layout()
                    
                    buf = io.BytesIO()
                    fig.savefig(buf, format='png', dpi=100)
                    graphs[f"network_graph_{iface}"] = base64.b64encode(buf.getvalue()).decode('utf-8')
                    plt.close(fig)
                    network_graphs_generated = True
                    print(f"  - 상세 네트워크 그래프 생성 완료: {iface}")
                except Exception as e:
                    print(f"  - ⚠️ {iface} 인터페이스 그래프 생성 중 오류: {e}")
                    import traceback
                    traceback.print_exc()

            if not network_graphs_generated:
                if inactive_up_interfaces:
                    reason = f"UP 상태인 인터페이스({', '.join(inactive_up_interfaces)})가 있지만, 기록된 트래픽이 없어 그래프를 생성하지 않았습니다."
                    graphs['network_graph_reason'] = reason
                else:
                    graphs['network_graph_reason'] = "데이터 부족: 'State: UP' 상태이면서 유효한 성능 데이터를 가진 네트워크 인터페이스가 없습니다."
        else:
             graphs['network_graph_reason'] = "데이터 없음: sar 파일에서 관련 통계 정보를 찾을 수 없습니다."
        
        # --- 디스크 I/O 그래프 ---
        if perf_data.get('disk') and len(perf_data['disk']) > 1:
            try:
                disk_agg = {}
                for d in perf_data['disk']:
                    ts = d['timestamp']
                    if ts not in disk_agg: disk_agg[ts] = {'read_kb': 0.0, 'write_kb': 0.0}
                    try:
                        disk_agg[ts]['read_kb'] += float(d.get('rkB_s', '0.0').replace(',', '.'))
                        disk_agg[ts]['write_kb'] += float(d.get('wkB_s', '0.0').replace(',', '.'))
                    except (ValueError, TypeError):
                        pass

                disk_data = sorted([{'timestamp': ts, **data} for ts, data in disk_agg.items()], key=lambda x: x['timestamp'])
                if len(disk_data) > 1:
                    timestamps = [d['timestamp'] for d in disk_data]
                    read_kB, write_kB = [d['read_kb'] for d in disk_data], [d['write_kb'] for d in disk_data]

                    fig, ax = plt.subplots(figsize=graph_style['figsize'])
                    ax.plot(timestamps, read_kB, color='#64B5CD', lw=2, label='Read (kB/s)')
                    ax.fill_between(timestamps, read_kB, color='#64B5CD', alpha=graph_style['alpha'])
                    ax.plot(timestamps, write_kB, color='#C44E52', lw=2, label='Write (kB/s)')
                    ax.fill_between(timestamps, write_kB, color='#C44E52', alpha=graph_style['alpha'])

                    ax.set_title('Disk I/O (kB/s)', fontsize=graph_style['title_fontsize'], weight='bold')
                    ax.set_ylabel('kB/s', fontsize=graph_style['label_fontsize'])
                    ax.legend(loc='upper left', frameon=True)
                    ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                    plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                    plt.tight_layout()

                    buf = io.BytesIO()
                    fig.savefig(buf, format='png', dpi=100)
                    graphs['disk_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                    plt.close(fig)
                    print("  - 디스크 I/O 그래프 생성 완료")
            except Exception as e:
                print(f"  - ⚠️ 디스크 I/O 그래프 생성 실패: {e}")
        
        # --- Load Average 그래프 ---
        if perf_data.get('load') and len(perf_data['load']) > 1:
            try:
                # Load Average 데이터는 파서에서 이미 float으로 변환됨
                load_data, timestamps = perf_data['load'], [d['timestamp'] for d in perf_data['load']]
                ldavg_1, ldavg_5, ldavg_15 = [d['ldavg-1'] for d in load_data], [d['ldavg-5'] for d in load_data], [d['ldavg-15'] for d in load_data]

                fig, ax = plt.subplots(figsize=graph_style['figsize'])
                ax.plot(timestamps, ldavg_1, label='Load Avg (1 min)', color='#4C72B0')
                ax.plot(timestamps, ldavg_5, label='Load Avg (5 min)', color='#55A868')
                ax.plot(timestamps, ldavg_15, label='Load Avg (15 min)', color='#C44E52')

                ax.set_title('System Load Average', fontsize=graph_style['title_fontsize'], weight='bold')
                ax.set_ylabel('Load', fontsize=graph_style['label_fontsize'])
                ax.legend(loc='upper left', frameon=True)
                ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
                plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
                plt.tight_layout()

                buf = io.BytesIO()
                fig.savefig(buf, format='png', dpi=100)
                graphs['load_average_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
                plt.close(fig)
                print("  - Load Average 그래프 생성 완료")
            except Exception as e:
                print(f"  - ⚠️ Load Average 그래프 생성 실패: {e}")

        print("✅ 모든 성능 그래프 생성 시도 완료.")
        return graphs

    def create_html_report(self, analysis_result: Dict[str, Any], sos_data: Dict[str, Any], graphs: Dict[str, str], output_dir: str, original_file: str) -> str:
        print("HTML 보고서 생성 중...")
        
        base_name = Path(original_file).stem.replace('.tar', '')
        report_file = Path(output_dir) / f"{base_name}_report.html"

        status = html.escape(analysis_result.get('system_status', 'N/A'))
        score = analysis_result.get('overall_health_score', 'N/A')
        summary = html.escape(analysis_result.get('summary', '정보 없음')).replace('\n', '<br>')
        critical_issues = analysis_result.get('critical_issues', [])
        warnings = analysis_result.get('warnings', [])
        recommendations = analysis_result.get('recommendations', [])
        
        system_info = sos_data.get('system_info', {})
        ip4_details = sos_data.get('ip4_details', [])
        storage_info = sos_data.get('storage', [])
        security_news = sos_data.get('security_news', [])
        network_details = sos_data.get('network_details', {})
        process_stats = sos_data.get('process_stats', {})


        status_colors = {"정상": "#28a745", "주의": "#ffc107", "위험": "#dc3545"}
        status_color = status_colors.get(status, "#6c757d")

        # --- Helper functions defined inside the method to avoid scope issues ---
        def create_list_table(items: List[str], empty_message: str) -> str:
            if not items:
                return f"<tr><td style='text-align:center;'>{html.escape(empty_message)}</td></tr>"
            rows = ""
            for item in items:
                rows += f"<tr><td>{html.escape(str(item))}</td></tr>"
            return rows

        def create_storage_rows(storage_list: List[Dict[str, str]]) -> str:
            rows = ""
            if not storage_list:
                return "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
            
            for index, item in enumerate(storage_list):
                bg_color_style = "background-color: #f8f9fa;" if index % 2 == 1 else ""

                # Main data row
                rows += f"""
                    <tr style="{bg_color_style}">
                        <td style="border-bottom: none; padding-bottom: 2px;">{html.escape(item.get('filesystem', 'N/A'))}</td>
                        <td style="border-bottom: none; padding-bottom: 2px;">{html.escape(item.get('size', 'N/A'))}</td>
                        <td style="border-bottom: none; padding-bottom: 2px;">{html.escape(item.get('used', 'N/A'))}</td>
                        <td style="border-bottom: none; padding-bottom: 2px;">{html.escape(item.get('avail', 'N/A'))}</td>
                        <td style="border-bottom: none; padding-bottom: 2px;">{html.escape(item.get('use%', 'N/A'))}</td>
                        <td style="border-bottom: none; padding-bottom: 2px;">{html.escape(item.get('mounted_on', 'N/A'))}</td>
                    </tr>
                """
                
                # Progress bar row
                use_pct_str = item.get('use%', '0%').replace('%', '')
                try:
                    use_pct = int(use_pct_str)
                    color = "#28a745"  # Green
                    if use_pct >= 90:
                        color = "#dc3545"  # Red
                    elif use_pct >= 80:
                        color = "#fd7e14"  # Orange
                    
                    rows += f"""
                        <tr style="{bg_color_style}">
                            <td colspan="6" style="padding: 2px 12px 12px 12px; border-top: none;">
                                <div class="progress-bar-container">
                                    <div class="progress-bar" style="width: {use_pct}%; background-color: {color};"></div>
                                </div>
                            </td>
                        </tr>
                    """
                except (ValueError, TypeError):
                     rows += f"""
                        <tr style="{bg_color_style}">
                            <td colspan="6" style="border-top: none;"></td>
                        </tr>
                     """
            return rows

        def create_security_news_rows(news_list):
            rows = ""
            if not news_list:
                return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
            
            if isinstance(news_list, list) and len(news_list) == 1 and 'reason' in news_list[0]:
                reason_text = html.escape(news_list[0]['reason'])
                return f"<tr><td colspan='4' style='text-align:center;'>{reason_text}</td></tr>"

            for item in news_list:
                cve_id = html.escape(item.get('CVE', 'N/A'))
                severity = item.get('severity', '').lower()
                matched_package = html.escape(item.get('matched_package', 'N/A'))
                
                severity_html = f"<td>{html.escape(item.get('severity', 'N/A'))}</td>"
                if severity == 'critical':
                    severity_html = f'<td style="text-align:center;"><div class="tooltip" style="font-size: 1.5em;">🔥<span class="tooltiptext">패키지: {matched_package}</span></div></td>'
                elif severity == 'important':
                    severity_html = f'<td style="text-align:center;"><div class="tooltip" style="font-size: 1.5em;">⚠️<span class="tooltiptext">패키지: {matched_package}</span></div></td>'

                rows += f"""
                    <tr>
                        <td><a href="https://access.redhat.com/security/cve/{cve_id}" target="_blank">{cve_id}</a></td>
                        {severity_html}
                        <td>{html.escape(item.get('public_date', 'N/A'))}</td>
                        <td>{html.escape(item.get('bugzilla_description', 'N/A'))}</td>
                    </tr>
                """
            return rows

        def create_recommendation_rows(recommendations_list):
            rows = ""
            if not recommendations_list:
                return "<tr><td colspan='4' style='text-align:center;'>데이터 없음</td></tr>"
            
            for item in recommendations_list:
                related_logs = item.get('related_logs', [])
                issue_html = html.escape(str(item.get('issue', 'N/A')))
                if related_logs:
                    logs_html = html.escape('\n'.join(related_logs))
                    issue_html += f' <div class="tooltip"><span class="log-icon">💬</span><span class="tooltiptext">{logs_html}</span></div>'

                rows += f"""
                    <tr>
                        <td>{html.escape(str(item.get('priority', 'N/A')))}</td>
                        <td>{html.escape(str(item.get('category', 'N/A')))}</td>
                        <td>{issue_html}</td>
                        <td>{html.escape(str(item.get('solution', 'N/A')))}</td>
                    </tr>
                """
            return rows
        
        def create_ethtool_rows(ethtool_data):
            rows = ""
            if not ethtool_data: return "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
            for iface, data in ethtool_data.items():
                errors_html = "없음"
                if 'errors' in data and data['errors']:
                    errors_html = "<br>".join([f"{k}: {v}" for k, v in data['errors'].items()])
                rows += f"""
                <tr>
                    <td>{html.escape(iface)}</td>
                    <td>{html.escape(data.get('speed', 'N/A'))}</td>
                    <td>{html.escape(data.get('link', 'N/A'))}</td>
                    <td>{html.escape(data.get('driver', 'N/A'))}</td>
                    <td>{html.escape(data.get('firmware', 'N/A'))}</td>
                    <td>{errors_html}</td>
                </tr>
                """
            return rows

        def create_bonding_rows(bonding_data):
            rows = ""
            if not bonding_data: return "<tr><td colspan='3' style='text-align:center;'>데이터 없음</td></tr>"
            for bond in bonding_data:
                rows += f"""
                <tr>
                    <td>{html.escape(bond.get('device', 'N/A'))}</td>
                    <td>{html.escape(bond.get('mode', 'N/A'))}</td>
                    <td>{html.escape(', '.join(bond.get('slaves', [])))}</td>
                </tr>
                """
            return rows

        def create_netdev_rows(netdev_data):
            rows = ""
            if not netdev_data: return "<tr><td colspan='9' style='text-align:center;'>데이터 없음</td></tr>"
            for dev in netdev_data:
                rows += f"""
                <tr>
                    <td>{html.escape(dev.get('iface', 'N/A'))}</td>
                    <td>{dev.get('rx_bytes', 0):,}</td>
                    <td>{dev.get('rx_packets', 0):,}</td>
                    <td style="color: red;">{dev.get('rx_errs', 0):,}</td>
                    <td style="color: red;">{dev.get('rx_drop', 0):,}</td>
                    <td>{dev.get('tx_bytes', 0):,}</td>
                    <td>{dev.get('tx_packets', 0):,}</td>
                    <td style="color: red;">{dev.get('tx_errs', 0):,}</td>
                    <td style="color: red;">{dev.get('tx_drop', 0):,}</td>
                </tr>
                """
            return rows

        def create_process_rows(process_list, title):
            rows = ""
            if not process_list: return f"<tr><td colspan='4' style='text-align:center;'>{title} 없음</td></tr>"
            for p in process_list:
                rows += f"""
                <tr>
                    <td>{html.escape(str(p.get('pid', '')))}</td>
                    <td>{html.escape(p.get('user', ''))}</td>
                    <td>{html.escape(str(p.get('cpu%', '')))}%</td>
                    <td>{html.escape(p.get('command', ''))}</td>
                </tr>
                """
            return rows

        ip4_details_rows = ""
        if not ip4_details:
            ip4_details_rows = "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
        else:
            for item in ip4_details:
                state_val = item.get('state', 'unknown').lower()
                state_html = f'<td>{html.escape(state_val.upper())}</td>'
                if 'up' in state_val:
                    state_html = '<td style="color: green; font-weight: bold;">UP</td>'
                elif 'down' in state_val:
                    state_html = '<td style="color: grey;">DOWN</td>'
                
                ip4_details_rows += f"""
                    <tr>
                        <td>{html.escape(item.get('iface', 'N/A'))}</td>
                        <td>{html.escape(item.get('master', 'N/A'))}</td>
                        <td>{html.escape(item.get('mac', 'N/A'))}</td>
                        <td>{html.escape(item.get('mtu', 'N/A'))}</td>
                        {state_html}
                        <td>{html.escape(item.get('ipv4', 'N/A'))}</td>
                    </tr>
                """
        
        graph_html = ""
        graph_html += '<div class="section"><h2>📊 성능 분석 요약</h2>'
        
        static_graph_items = {
            'cpu_graph': 'CPU Usage (%)', 
            'memory_graph': 'Memory Usage (KB)', 
            'load_average_graph': 'System Load Average',
            'disk_graph': 'Disk I/O (kB/s)'
        }
        has_any_graph = False
        for key, title in static_graph_items.items():
            if key in graphs:
                has_any_graph = True
                graph_html += f'<div class="graph-container"><h3>{title}</h3><img src="data:image/png;base64,{graphs[key]}" alt="{title} Graph"></div>'

        network_graph_keys = sorted([k for k in graphs.keys() if k.startswith('network_graph_')])
        if 'network_graph_reason' in graphs:
             graph_html += f'<div class="graph-container"><h3>Network Traffic</h3><p style="text-align:center; color: #888;">{html.escape(graphs["network_graph_reason"])}</p></div>'
        
        for key in network_graph_keys:
            if key == 'network_graph_reason': continue
            has_any_graph = True
            iface_name = html.escape(key.replace('network_graph_', ''))
            graph_title = f'Network Traffic ({iface_name})'
            graph_html += f'<div class="graph-container"><h3>{graph_title}</h3><img src="data:image/png;base64,{graphs[key]}" alt="{graph_title} Graph"></div>'

        if not has_any_graph and 'network_graph_reason' not in graphs:
            graph_html += "<p style='text-align:center;'>분석할 수 있는 성능 데이터가 부족하여 그래프를 생성할 수 없습니다.</p>"
        graph_html += '</div>'
        
        html_template = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 분석 보고서</title>
    <style>
        body {{ font-family: 'Malgun Gothic', '맑은 고딕', sans-serif; background-color: #f4f7f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: #fff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); overflow: hidden; }}
        header {{ background-color: #343a40; color: white; padding: 20px; text-align: center; }}
        header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 20px; }}
        .section {{ margin-bottom: 25px; }}
        .section h2 {{ font-size: 20px; border-left: 5px solid #007bff; padding-left: 10px; margin-bottom: 15px; color: #343a40; }}
        .section h3 {{ font-size: 16px; color: #495057; margin-top: 20px; margin-bottom: 10px;}}
        .graph-container {{ margin-bottom: 20px; padding: 15px; border: 1px solid #e0e0e0; border-radius: 5px; background-color: #fafafa; }}
        .graph-container h3 {{ text-align: center; margin-top: 0; color: #333; }}
        .graph-container img {{ width: 100%; max-width: 900px; display: block; margin: auto; border-radius: 4px; }}
        .data-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; font-size: 14px; }}
        .data-table th, .data-table td {{ border: 1px solid #dee2e6; padding: 12px; text-align: left; word-wrap: break-word; }}
        .data-table thead th {{ background-color: #f8f9fa; color: #495057; font-weight: 600; }}
        .fixed-layout {{ table-layout: fixed; }}
        .summary-table th:nth-of-type(1) {{ width: 20%; }}
        .network-table th:nth-of-type(1) {{ width: 15%; }} .network-table th:nth-of-type(2) {{ width: 10%; }} .network-table th:nth-of-type(3) {{ width: 20%; }} .network-table th:nth-of-type(4) {{ width: 8%; }} .network-table th:nth-of-type(5) {{ width: 10%; }}
        .storage-table th:nth-of-type(1) {{ width: 30%; }}
        .recommendations-table th:nth-of-type(1) {{ width: 10%; }} .recommendations-table th:nth-of-type(2) {{ width: 15%; }} .recommendations-table th:nth-of-type(3) {{ width: 35%; }}
        .security-table th:nth-of-type(1) {{ width: 18%; }} .security-table th:nth-of-type(2) {{ width: 8%; }} .security-table th:nth-of-type(3) {{ width: 10%; }}
        .security-table td:nth-of-type(2), .security-table td:nth-of-type(3) {{ text-align: center; }}
        .ai-status {{ font-size: 1.2em; font-weight: bold; color: {status_color}; }}
        footer {{ text-align: center; padding: 15px; font-size: 12px; color: #888; background-color: #f4f7f9; }}
        .tooltip {{ position: relative; display: inline-block; cursor: pointer; }}
        .tooltip .tooltiptext {{ visibility: hidden; width: 450px; background-color: #333; color: #fff; text-align: left; border-radius: 6px; padding: 10px; position: absolute; z-index: 1; bottom: 125%; left: 50%; margin-left: -225px; opacity: 0; transition: opacity 0.3s; font-size: 12px; white-space: pre-wrap; }}
        .tooltip:hover .tooltiptext {{ visibility: visible; opacity: 1; }}
        .log-icon {{ font-size: 14px; margin-left: 5px; color: #007bff; }}
        .progress-bar-container {{ height: 10px; width: 100%; background-color: #e9ecef; border-radius: 5px; overflow: hidden; }}
        .progress-bar {{ height: 100%; border-radius: 5px; transition: width 0.4s ease-in-out; }}
    </style>
</head>
<body>
    <div class="container">
        <header><h1>S-Core System Report</h1></header>
        <div class="content">
            <div class="section">
                <h2>ℹ️ 시스템 요약</h2>
                <table class="data-table summary-table fixed-layout">
                    <tbody>
                        <tr><th>Hostname</th><td>{html.escape(system_info.get('hostname', 'N/A'))}</td></tr>
                        <tr><th>OS Version</th><td>{html.escape(system_info.get('os_version', 'N/A'))}</td></tr>
                        <tr><th>Kernel</th><td>{html.escape(system_info.get('kernel', 'N/A'))}</td></tr>
                        <tr><th>System Model</th><td>{html.escape(system_info.get('system_model', 'N/A'))}</td></tr>
                        <tr><th>CPU</th><td>{html.escape(system_info.get('cpu', 'N/A'))}</td></tr>
                        <tr><th>Memory</th><td>{html.escape(system_info.get('memory', 'N/A'))}</td></tr>
                        <tr><th>Uptime</th><td>{html.escape(system_info.get('uptime', 'N/A'))}</td></tr>
                        <tr><th>Last Boot</th><td>{html.escape(system_info.get('last_boot', 'N/A'))}</td></tr>
                    </tbody>
                </table>
            </div>
            {graph_html}
            <div class="section">
                <h2>🌐 네트워크 정보</h2>
                <h3>IP4 상세 정보</h3>
                <table class="data-table network-table fixed-layout">
                    <thead><tr><th>Interface</th><th>Master IF</th><th>MAC Address</th><th>MTU</th><th>State</th><th>IPv4 Address</th></tr></thead>
                    <tbody>{ip4_details_rows}</tbody>
                </table>
                <h3>라우팅 테이블</h3>
                <table class="data-table">
                    <thead><tr><th>Destination</th><th>Gateway</th><th>Device</th><th>Source</th></tr></thead>
                    <tbody>{ "".join(f"<tr><td>{html.escape(r.get('destination', ''))}</td><td>{html.escape(r.get('gateway', ''))}</td><td>{html.escape(r.get('device', ''))}</td><td>{html.escape(r.get('source', ''))}</td></tr>" for r in system_info.get('routing_table', [])) }</tbody>
                </table>
                <h3>ETHTOOL 상태</h3>
                <table class="data-table">
                    <thead><tr><th>Interface</th><th>Speed</th><th>Link Detected</th><th>Driver</th><th>Firmware Version</th><th>Errors</th></tr></thead>
                    <tbody>{ create_ethtool_rows(network_details.get('ethtool', {})) }</tbody>
                </table>
                 <h3>NETDEV 통계</h3>
                <table class="data-table">
                    <thead><tr><th>Iface</th><th>RX Bytes</th><th>RX Pkts</th><th>RX Errs</th><th>RX Drop</th><th>TX Bytes</th><th>TX Pkts</th><th>TX Errs</th><th>TX Drop</th></tr></thead>
                    <tbody>{ create_netdev_rows(network_details.get('netdev', [])) }</tbody>
                </table>
                <h3>소켓 통계</h3>
                <table class="data-table">
                    <tbody>{ create_list_table(network_details.get('sockstat', []), "데이터 없음") }</tbody>
                </table>
                <h3>네트워크 본딩</h3>
                <table class="data-table">
                    <thead><tr><th>Device</th><th>Mode</th><th>Slaves</th></tr></thead>
                    <tbody>{ create_bonding_rows(network_details.get('bonding', [])) }</tbody>
                </table>
            </div>
            <div class="section">
                <h2>⚙️ 프로세스 및 리소스</h2>
                <h3>리소스 사용 현황 (상위 5개 사용자)</h3>
                <table class="data-table">
                    <thead><tr><th>User</th><th>CPU%</th><th>MEM%</th><th>RSS</th></tr></thead>
                    <tbody>{"".join(f"<tr><td>{html.escape(u.get('user', ''))}</td><td>{html.escape(u.get('cpu%', ''))}</td><td>{html.escape(u.get('mem%', ''))}</td><td>{html.escape(u.get('rss', ''))}</td></tr>" for u in process_stats.get('by_user', []))}</tbody>
                </table>
                <h3>Top 5 CPU 사용 프로세스</h3>
                <table class="data-table">
                     <thead><tr><th>PID</th><th>User</th><th>CPU%</th><th>Command</th></tr></thead>
                    <tbody>{create_process_rows(process_stats.get('top_cpu', []), "CPU 사용량 높은 프로세스")}</tbody>
                </table>
                 <h3>Top 5 메모리 사용 프로세스</h3>
                <table class="data-table">
                    <thead><tr><th>PID</th><th>User</th><th>MEM%</th><th>Command</th></tr></thead>
                    <tbody>{create_process_rows(process_stats.get('top_mem', []), "메모리 사용량 높은 프로세스")}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>💾 스토리지 및 파일 시스템</h2>
                <table class="data-table storage-table fixed-layout">
                    <thead><tr><th>Filesystem</th><th>Size</th><th>Used</th><th>Avail</th><th>Use%</th><th>Mounted on</th></tr></thead>
                    <tbody>{create_storage_rows(storage_info)}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>🚨 AI 분석: 심각한 이슈 ({len(critical_issues)}개)</h2>
                <table class="data-table">
                    <thead><tr><th>상세 내용</th></tr></thead>
                    <tbody>{create_list_table(critical_issues, "발견된 심각한 이슈가 없습니다.")}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>⚠️ AI 분석: 경고 사항 ({len(warnings)}개)</h2>
                <table class="data-table">
                    <thead><tr><th>상세 내용</th></tr></thead>
                    <tbody>{create_list_table(warnings, "특별한 경고 사항이 없습니다.")}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>💡 AI 분석: 권장사항 ({len(recommendations)}개)</h2>
                <table class="data-table recommendations-table fixed-layout">
                    <thead><tr><th>우선순위</th><th>카테고리</th><th>문제점 💬</th><th>해결 방안</th></tr></thead>
                    <tbody>{create_recommendation_rows(recommendations)}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>🤖 AI 종합 분석</h2>
                <table class="data-table summary-table fixed-layout">
                    <tbody>
                        <tr><th>종합 상태</th><td><span class="ai-status">{status}</span></td></tr>
                        <tr><th>건강도 점수</th><td>{score}/100</td></tr>
                        <tr><th>요약</th><td>{summary}</td></tr>
                    </tbody>
                </table>
            </div>
            <div class="section">
                <h2>🛡️ 보안 뉴스 (가장 중요한 CVE 최대 5개) <span style="font-size: 0.7em; font-weight: normal;">(🔥 Critical, ⚠️ Important)</span></h2>
                <table class="data-table security-table fixed-layout">
                    <thead><tr><th>CVE 식별자</th><th>심각도</th><th>생성일</th><th>위협 및 영향 요약</th></tr></thead>
                    <tbody>{create_security_news_rows(security_news)}</tbody>
                </table>
            </div>
        </div>
        <footer>보고서 생성 시각: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</footer>
    </div>
</body>
</html>"""
        try:
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_template)
            print(f"✅ HTML 보고서 생성 완료: {report_file}")
            return str(report_file)
        except Exception as e:
            print(f"❌ HTML 보고서 생성 실패: {e}")
            raise

def win_safe_filter(member, path):
    member.name = member.name.replace(':', '_')
    return member

def decompress_sosreport(archive_path: str, extract_dir: str) -> str:
    """
    sosreport 압축 파일을 해제합니다.
    Linux 환경에서는 시스템 'tar' 명령어를 '--no-same-owner' 옵션과 함께 사용하여
    추출된 파일들이 현재 스크립트를 실행하는 사용자 소유가 되도록 합니다.
    """
    print(f"압축 파일 해제 중: {archive_path}")
    
    if sys.platform == "win32":
        try:
            with tarfile.open(archive_path, 'r:*') as tar:
                tar.extractall(path=extract_dir, filter=win_safe_filter)
            print(f"✅ 압축 해제 완료 (Windows 방식): {extract_dir}")
            return extract_dir
        except tarfile.TarError as e:
            raise Exception(f"압축 파일 해제 실패: {e}")
    
    else:
        if not shutil.which("tar"):
            raise EnvironmentError("'tar' 명령어를 찾을 수 없습니다. 스크립트 실행에 필수적입니다.")
        
        command = ["tar", "--no-same-owner", "-xf", archive_path, "-C", extract_dir]
        
        try:
            print(f"실행 명령어: {' '.join(command)}")
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print(f"✅ 압축 해제 완료 (Linux 방식): {extract_dir}")
            return extract_dir
        except subprocess.CalledProcessError as e:
            error_message = f"""압축 파일 해제 실패: 'tar' 명령어 실행 중 오류 발생.
  - Return Code: {e.returncode}
  - STDOUT: {e.stdout.decode(errors='ignore') if e.stdout else ''}
  - STDERR: {e.stderr.decode(errors='ignore') if e.stderr else ''}"""
            raise Exception(error_message)


def main():
    parser = argparse.ArgumentParser(description='sosreport 압축 파일 AI 분석 및 보고서 생성 도구', formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('sosreport_archive', nargs='?', help='분석할 sosreport 압축 파일 경로 (.tar.xz, .tar.gz 등)')
    parser.add_argument('--llm-url', required=True, help='LLM 서버의 기본 URL')
    parser.add_argument('--endpoint-path', default='/v1/chat/completions', help='API의 Chat Completions 엔드포인트 경로')
    parser.add_argument('--model', help='사용할 LLM 모델 이름 (list-models 사용 시 불필요)')
    parser.add_argument('--api-token', help='API 인증 토큰. LLM_API_TOKEN 환경 변수로도 설정 가능')
    parser.add_argument('--output', '-o', default='output', help='결과 저장 디렉토리 (기본값: output)')
    parser.add_argument('--no-html', action='store_true', help='HTML 보고서 생성을 비활성화합니다.')
    parser.add_argument('--list-models', action='store_true', help='서버에서 사용 가능한 모델 목록을 조회합니다.')
    parser.add_argument('--test-only', action='store_true', help='LLM 연결 테스트만 수행 (모델 이름 필요)')
    
    args = parser.parse_args()
    
    if sys.platform != "win32" and os.geteuid() != 0:
        print("⚠️ 경고: 이 스크립트는 'sudo' 또는 root 권한으로 실행하는 것을 권장합니다.", file=sys.stderr)
        print("   만약 'sudo' 없이 실행하려면, 시스템에 'tar' 명령어가 설치되어 있어야 합니다.", file=sys.stderr)

    api_token = args.api_token or os.getenv('LLM_API_TOKEN')
    
    if not plt:
        print("경고: 'matplotlib' 라이브러리를 찾을 수 없어 그래프 생성 기능이 비활성화됩니다.", file=sys.stderr)
        print("'pip install matplotlib' 명령어로 설치해주세요.", file=sys.stderr)
    
    analyzer = AIAnalyzer(
        llm_url=args.llm_url, model_name=args.model,
        endpoint_path=args.endpoint_path, api_token=api_token,
        output_dir=args.output
    )

    if args.list_models:
        analyzer.list_available_models()
        sys.exit(0)

    if args.test_only:
        if not args.model: parser.error("--test_only 옵션은 --model 인자가 필요합니다.")
        if analyzer.check_llm_service() and analyzer.test_llm_connection():
            print("\n✅ LLM 서비스가 정상적으로 작동합니다.")
        else:
            print("\n❌ LLM 서비스에 문제가 있습니다.")
        sys.exit(0)

    if not args.sosreport_archive:
        parser.error("분석할 sosreport 압축 파일 경로를 입력해야 합니다.")
    if not args.model:
        parser.error("분석을 위해서는 --model 인자가 필요합니다.")
    
    if not os.path.exists(args.sosreport_archive):
        print(f"❌ 입력된 압축 파일을 찾을 수 없습니다: {args.sosreport_archive}")
        sys.exit(1)

    os.makedirs(args.output, exist_ok=True)
    
    temp_extract_dir = None
    try:
        temp_extract_dir = tempfile.mkdtemp(prefix=f"sos_{Path(args.sosreport_archive).stem}_")
        print(f"시스템 임시 경로에 작업 디렉토리 생성: {temp_extract_dir}")
        
        decompress_sosreport(args.sosreport_archive, str(temp_extract_dir))
        
        parser = SosreportParser(str(temp_extract_dir))
        sos_data = parser.parse()

        base_name = Path(args.sosreport_archive).stem.replace('.tar', '')
        
        parsed_data_path = Path(args.output) / f"{base_name}_extracted_data.json"
        try:
            with open(parsed_data_path, 'w', encoding='utf-8') as f:
                json.dump(sos_data, f, indent=2, ensure_ascii=False)
            print(f"✅ 전체 추출 데이터 JSON 파일로 저장 완료: {parsed_data_path}")
        except Exception as e:
            print(f"❌ 전체 추출 데이터 JSON 저장 실패: {e}")

        prompt = analyzer.create_analysis_prompt(sos_data)
        result = analyzer.perform_ai_analysis(prompt)
        print("✅ AI 시스템 분석 완료!")
        
        sos_data['ai_analysis'] = result
        sos_data['security_news'] = analyzer.fetch_security_news(sos_data)
        graphs = analyzer.create_performance_graphs(sos_data)
        
        results = {}
        if not args.no_html:
            html_path = analyzer.create_html_report(result, sos_data, graphs, args.output, args.sosreport_archive)
            results['html_file'] = html_path
        
        results['extracted_data_file'] = str(parsed_data_path)

        print("\n분석이 성공적으로 완료되었습니다!")
        if 'html_file' in results:
            print(f"  - HTML 보고서: {results['html_file']}")
        if 'extracted_data_file' in results:
            print(f"  - 전체 추출 데이터 (JSON): {results['extracted_data_file']}")

    except Exception as e:
        print(f"\n❌ 전체 분석 과정 중 오류 발생: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        if temp_extract_dir and os.path.exists(temp_extract_dir):
            print(f"임시 디렉토리 정리 시도: {temp_extract_dir}")
            try:
                shutil.rmtree(temp_extract_dir)
                print("✅ 임시 디렉토리 정리 완료.")
            except Exception as e:
                print(f"\n❌ 임시 디렉토리 자동 정리에 실패했습니다: {e}")
                print("   sudo rm -rf {temp_extract_dir}\n")

if __name__ == "__main__":
    main()
