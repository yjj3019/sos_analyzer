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

# --- 웹 스크레이핑 및 XML 파싱을 위한 라이브러리 ---
# "pip install beautifulsoup4 lxml" 명령어로 설치 필요
try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

class SosreportParser:
    """sosreport 압축 해제 후 디렉토리에서 데이터를 파싱하여 JSON 구조로 만듭니다."""
    def __init__(self, extract_path: str):
        self.extract_path = Path(extract_path)
        subdirs = [d for d in self.extract_path.iterdir() if d.is_dir()]
        self.base_path = subdirs[0] if len(subdirs) == 1 else self.extract_path
        print(f"sosreport 데이터 분석 경로: {self.base_path}")
        
        # sosreport 수집 날짜를 기준으로 sar 파일 패턴 생성
        date_content = self._read_file(['sos_commands/general/date', 'date'])
        self.report_date = datetime.now() # Fallback

        if date_content != 'N/A':
            try:
                # 다양한 날짜 형식 파싱 시도 (예: Wed Aug 27 10:50:01 KST 2025)
                match = re.search(r'([A-Za-z]{3})\s+(\d{1,2})\s+[\d:]+\s+.*?(\d{4})', date_content)
                if match:
                    month_abbr, day, year = match.groups()
                    month_map = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6, 'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
                    month = month_map.get(month_abbr)
                    if month:
                        self.report_date = datetime(int(year), month, int(day))
                        print(f"✅ sosreport 수집일 감지: {self.report_date.strftime('%Y-%m-%d')}")
                    else:
                        raise ValueError(f"알 수 없는 월 약어: {month_abbr}")
                else:
                     raise ValueError("인식할 수 없는 날짜 형식")
            except Exception as e:
                print(f"⚠️ 경고: sosreport 수집일({date_content}) 파싱 실패: {e}. 오늘 날짜를 기준으로 합니다.")
                self.report_date = datetime.now()
        else:
            print("⚠️ 경고: 'date' 파일을 찾을 수 없어 오늘 날짜 기준으로 sar 파일을 검색합니다.")
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
        명시된 우선순위에 따라 sosreport 수집 당일의 sar 데이터를 찾아 파싱합니다.
        """
        print("sar 성능 데이터 파싱 중...")
        
        # 사용자가 요청한 파일 검색 순서
        search_paths = [
            {'path': f'var/log/sa/sar{self.report_day_str}', 'type': 'text'},
            {'path': f'var/log/sa/sar{self.report_full_date_str}', 'type': 'text'},
            {'path': f'sos_commands/sar/sar{self.report_day_str}', 'type': 'text'},
            {'path': f'sos_commands/sar/sa{self.report_day_str}.xml', 'type': 'xml'},
            {'path': f'sos_commands/sar/sa{self.report_full_date_str}.xml', 'type': 'xml'},
        ]

        for candidate in search_paths:
            file_path = self.base_path / candidate['path']
            file_type = candidate['type']

            if file_path.exists():
                print(f"  -> 파일 발견. 파싱 시도: {candidate['path']} ({file_type})")
                try:
                    content = file_path.read_text(encoding='utf-8', errors='ignore')
                    if not content.strip():
                        print("    - 파일 내용이 비어있어 건너뜁니다.")
                        continue

                    if file_type == 'xml':
                        if not BeautifulSoup:
                            print("    - XML 파서(lxml)가 없어 건너뜁니다.")
                            continue
                        soup = BeautifulSoup(content, 'lxml-xml')
                        performance_data = self._parse_sar_xml_content(soup)
                    else: # text
                        performance_data = self._parse_sar_text_content(content)

                    if any(performance_data.values()):
                        print(f"✅ {file_type.upper()} sar 데이터 파싱 성공: {file_path.name}")
                        return performance_data
                    else:
                        print(f"    - {file_path.name} 파일에서 유효한 성능 데이터를 추출하지 못했습니다.")

                except Exception as e:
                    print(f"⚠️ {file_type.upper()} sar 파일({file_path.name}) 파싱 중 오류 발생: {e}")
        
        print(f"  -> 지정된 형식의 sar 파일을 찾지 못했거나 파싱에 실패했습니다. 종합 sar 데이터(sar -A)로 대체합니다.")
        sar_A_content = self._read_file(['sos_commands/monitoring/sar_-A'])
        if sar_A_content != 'N/A' and sar_A_content.strip():
            performance_data = self._parse_sar_text_content(sar_A_content)
            if any(performance_data.values()):
                print("✅ 종합 sar 데이터(sar -A) 파싱 완료.")
                return performance_data
        
        print("❌ 분석할 수 있는 sar 데이터를 찾지 못했습니다.")
        return {'cpu': [], 'memory': [], 'network': [], 'disk': []}

    def _parse_sar_xml_content(self, soup: BeautifulSoup) -> Dict:
        """BeautifulSoup 객체에서 sar 성능 데이터를 추출합니다."""
        performance_data = {'cpu': [], 'memory': [], 'network': [], 'disk': []}
        stats = soup.find_all('statistic')
        for stat in stats:
            time_str = stat.get('time', '00:00:00')
            ampm_str = stat.get('ampm', '')
            timestamp = f"{time_str} {ampm_str}".strip()
            
            cpu_load = stat.find('cpu-load', {'cpu': 'all'})
            if cpu_load:
                performance_data['cpu'].append({
                    'timestamp': timestamp, 'user': float(cpu_load.find('user').text),
                    'system': float(cpu_load.find('system').text), 'iowait': float(cpu_load.find('iowait').text),
                    'idle': float(cpu_load.find('idle').text)
                })

            memory = stat.find('memory')
            if memory and memory.find('memused-percent'):
                performance_data['memory'].append({
                    'timestamp': timestamp, 'memused_percent': float(memory.find('memused-percent').text)
                })

            network = stat.find('network')
            if network:
                net_agg = {'rxkB': 0.0, 'txkB': 0.0}
                for dev in network.find_all('net-dev'):
                    if dev.get('iface') != 'lo':
                        net_agg['rxkB'] += float(dev.find('rx-kB').text) if dev.find('rx-kB') else 0.0
                        net_agg['txkB'] += float(dev.find('tx-kB').text) if dev.find('tx-kB') else 0.0
                if net_agg['rxkB'] > 0 or net_agg['txkB'] > 0:
                        performance_data['network'].append({'timestamp': timestamp, **net_agg})

            disk = stat.find('disk')
            if disk:
                disk_agg = {'read_kB': 0.0, 'write_kB': 0.0, 'util_percent': 0.0}
                for dev in disk.find_all('io'):
                    disk_agg['read_kB'] += float(dev.find('read-kB').text) if dev.find('read-kB') else 0.0
                    disk_agg['write_kB'] += float(dev.find('write-kB').text) if dev.find('write-kB') else 0.0
                    disk_agg['util_percent'] += float(dev.find('util-percent').text) if dev.find('util-percent') else 0.0
                if disk_agg['read_kB'] > 0 or disk_agg['write_kB'] > 0:
                    performance_data['disk'].append({'timestamp': timestamp, **disk_agg})
        return performance_data

    def _parse_sar_text_content(self, sar_content: str) -> Dict[str, List[Dict[str, Any]]]:
        """주어진 sar 텍스트 내용을 파싱합니다."""
        performance_data = {'cpu': [], 'memory': [], 'network': [], 'disk': []}

        cpu_section = re.search(r'(\d{2}:\d{2}:\d{2}\s+(?:AM|PM)?\s+CPU\s+%user\s+%nice\s+%system\s+%iowait\s+%steal\s+%idle\n(?:.*\n)+?)(?=\n\n|\Z)', sar_content, re.MULTILINE)
        if cpu_section:
            for line in cpu_section.group(1).strip().split('\n'):
                parts = line.split()
                if len(parts) < 8 or not parts[0][0].isdigit(): continue

                ts_parts, data_parts = [], []
                for part in parts:
                    if ':' in part or part in ('AM', 'PM'): ts_parts.append(part)
                    elif re.match(r'^[0-9.]+$', part) or part == 'all': data_parts.append(part)

                if 'all' not in data_parts: continue
                
                try:
                    timestamp = ' '.join(ts_parts)
                    user_idx = data_parts.index('all') + 1
                    performance_data['cpu'].append({
                        'timestamp': timestamp, 'user': float(data_parts[user_idx]), 
                        'system': float(data_parts[user_idx+2]), 'iowait': float(data_parts[user_idx+3]), 
                        'idle': float(data_parts[user_idx+5])
                    })
                except (ValueError, IndexError): continue

        mem_section = re.search(r'(\d{2}:\d{2}:\d{2}\s+(?:AM|PM)?\s+kbmemfree\s+kbmemused\s+%memused\s+kbbuffers\s+kbcached\s+kbcommit\s+%commit\n(?:.*\n)+?)(?=\n\n|\Z)', sar_content, re.MULTILINE)
        if mem_section:
            for line in mem_section.group(1).strip().split('\n'):
                parts = line.split()
                if len(parts) < 5 or not parts[0][0].isdigit(): continue
                
                ts_parts, data_parts = [], []
                for part in parts:
                    if ':' in part or part in ('AM', 'PM'): ts_parts.append(part)
                    elif re.match(r'^[0-9.]+$', part): data_parts.append(part)

                if len(data_parts) < 3: continue

                try:
                    timestamp = ' '.join(ts_parts)
                    performance_data['memory'].append({'timestamp': timestamp, 'memused_percent': float(data_parts[2])})
                except (ValueError, IndexError): continue

        net_section = re.search(r'(\d{2}:\d{2}:\d{2}\s+(?:AM|PM)?\s+IFACE\s+rxpck/s\s+txpck/s\s+rxkB/s\s+txkB/s\s+rxcmp/s\s+txcmp/s\s+rxmcst/s\n(?:.*\n)+?)(?=\n\n|\Z)', sar_content, re.MULTILINE)
        if net_section:
            net_agg = {}
            for line in net_section.group(1).strip().split('\n'):
                parts = line.split()
                if len(parts) < 7 or not parts[0][0].isdigit(): continue

                ts_parts, data_parts, iface = [], [], ''
                for part in parts:
                    if ':' in part or part in ('AM', 'PM'): ts_parts.append(part)
                    elif re.match(r'^[a-zA-Z0-9.-]+$', part) and not part.replace('.','',1).isdigit(): iface = part
                    elif re.match(r'^[0-9./]+$', part): data_parts.append(part)

                if iface in ('lo', 'IFACE') or not iface: continue
                
                try:
                    timestamp = ' '.join(ts_parts)
                    if timestamp not in net_agg: net_agg[timestamp] = {'rxkB': 0.0, 'txkB': 0.0}
                    net_agg[timestamp]['rxkB'] += float(data_parts[2])
                    net_agg[timestamp]['txkB'] += float(data_parts[3])
                except (ValueError, IndexError): continue
            for ts, data in net_agg.items():
                performance_data['network'].append({'timestamp': ts, **data})
        
        disk_section = re.search(r'(\d{2}:\d{2}:\d{2}\s+(?:AM|PM)?\s+DEV\s+tps\s+rkB/s\s+wkB/s\s+areq-sz\s+aqu-sz\s+await\s+%util\n(?:.*\n)+?)(?=\n\n|\Z)', sar_content, re.MULTILINE)
        if disk_section:
            disk_agg = {}
            for line in disk_section.group(1).strip().split('\n'):
                parts = line.split()
                if len(parts) < 9 or not parts[0][0].isdigit(): continue
                
                ts_parts, data_parts = [], []
                for part in parts:
                    if ':' in part or part in ('AM', 'PM'): ts_parts.append(part)
                    elif re.match(r'^[0-9.]+$', part): data_parts.append(part)

                if len(data_parts) < 8: continue
                
                try:
                    timestamp = ' '.join(ts_parts)
                    if timestamp not in disk_agg: disk_agg[timestamp] = {'read_kB': 0.0, 'write_kB': 0.0, 'util_percent': 0.0}
                    disk_agg[timestamp]['read_kB'] += float(data_parts[1])
                    disk_agg[timestamp]['write_kB'] += float(data_parts[2])
                    disk_agg[timestamp]['util_percent'] += float(data_parts[7])
                except (ValueError, IndexError): continue
            for ts, data in disk_agg.items():
                performance_data['disk'].append({'timestamp': ts, **data})

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
        """matplotlib에서 한글을 지원하기 위한 폰트 설정"""
        if not plt:
            return
        
        font_paths = fm.findSystemFonts(fontpaths=None, fontext='ttf')
        korean_font_path = None
        for path in font_paths:
            if 'nanum' in path.lower() or 'malgun' in path.lower():
                korean_font_path = path
                break
        
        if korean_font_path:
            try:
                fm.fontManager.addfont(korean_font_path)
                font_name = fm.FontProperties(fname=korean_font_path).get_name()
                plt.rc('font', family=font_name)
                plt.rc('axes', unicode_minus=False)
                print(f"✅ 한글 폰트 설정 완료: {font_name}")
            except Exception as e:
                print(f"⚠️ 한글 폰트 설정 중 오류 발생: {e}. 그래프 제목이 깨질 수 있습니다.")
        else:
            print("⚠️ 경고: '나눔고딕' 또는 '맑은 고딕' 폰트를 찾을 수 없습니다. 그래프의 한글이 깨질 수 있습니다.")


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
            print(f"LLM API 호출 중... ({self.completion_url})")

            if is_news_request:
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

            if response.status_code != 200:
                raise ValueError(f"API 호출 실패: HTTP {response.status_code}, 내용: {response.text[:500]}")
            
            result = response.json()
            if 'choices' not in result or not result['choices']:
                raise ValueError(f"API 응답에 'choices' 키가 없거나 비어 있습니다. 응답: {result}")

            ai_response = result['choices'][0]['message']['content']
            
            if is_news_request:
                with open(llm_log_path, 'a', encoding='utf-8') as f:
                    f.write(ai_response)

            return self._parse_ai_response(ai_response)
        except (requests.exceptions.RequestException, ValueError) as e:
            raise Exception(f"AI 분석 중 오류 발생: {e}")

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

        prompt = f"""당신은 Red Hat Enterprise Linux 시스템 전문가입니다. 다음 sosreport 분석 데이터와 시스템 로그를 종합적으로 검토하고 전문적인 진단을 제공해주세요.

## 분석 데이터
```json
{data_str}
```

## 분석 가이드라인
- **심각한 이슈(critical_issues) 판단 기준**: 로그 내용에 'panic', 'segfault', 'out of memory', 'hardware error', 'i/o error', 'call trace'와 같은 명백한 시스템 장애나 데이터 손상 가능성을 암시하는 키워드가 포함된 경우, **반드시 '심각한 이슈'로 분류**해야 합니다.
- **경고(warnings) 판단 기준**: 당장 시스템 장애를 일으키지는 않지만, 잠재적인 문제로 발전할 수 있거나 주의가 필요한 로그(예: 'warning', 'failed' 등)는 '경고'로 분류합니다.

## 분석 요청
위 데이터와 **분석 가이드라인**을 바탕으로, 특히 **`recent_log_warnings_and_errors`에 포함된 시스템 로그 메시지를 주의 깊게 분석**하여 다음 JSON 형식에 맞춰 종합적인 시스템 분석을 제공해주세요.
- 로그에서 발견된 구체적인 오류나 경고를 `critical_issues` 또는 `warnings` 항목에 반드시 반영해야 합니다.
- `recommendations`의 각 항목을 작성할 때, 어떤 로그 메시지를 근거로 해당 권장사항을 만들었는지 `related_logs` 필드에 명시해야 합니다.

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

**중요**: 당신의 응답은 반드시 위 JSON 형식이어야 합니다. 다른 설명이나 텍스트 없이, `{{`로 시작해서 `}}`로 끝나는 순수한 JSON 객체만 출력해야 합니다. `related_logs` 필드는 근거가 된 로그가 없을 경우 빈 배열 `[]`로 출력해주세요.
"""
        return prompt

    def _parse_ai_response(self, ai_response: str) -> Any:
        print("AI 응답 파싱 중...")
        
        if not ai_response or not ai_response.strip():
            raise ValueError("AI 응답이 비어 있습니다.")

        refusal_patterns = ["i'm sorry", "i cannot", "i can't", "i am unable", "죄송합니다", "할 수 없습니다"]
        if any(pattern in ai_response.lower() for pattern in refusal_patterns):
            raise ValueError(f"LLM이 요청 처리를 거부했습니다. (응답: '{ai_response.strip()}')")

        try:
            cleaned_response = re.sub(r'^```(json)?\s*|\s*```$', '', ai_response.strip())
            start = cleaned_response.find('{')
            end = cleaned_response.rfind('}')
            
            if start == -1 or end == -1 or end < start:
                raise ValueError("응답에서 유효한 JSON 객체({{ ... }})를 찾을 수 없습니다.")
            
            json_str = cleaned_response[start:end+1]
            return json.loads(json_str)
        except json.JSONDecodeError as e:
            error_message = f"AI 응답 JSON 파싱 실패: {e}.\n--- 원본 응답 ---\n{ai_response}\n----------------"
            print(error_message)
            raise ValueError(error_message)
        except ValueError as e:
            error_message = f"AI 응답 처리 중 오류 발생: {e}.\n--- 원본 응답 ---\n{ai_response}\n----------------"
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

            api_url = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
            print(f"Red Hat CVE API 호출: {api_url}")
            response = requests.get(api_url, timeout=120)
            if response.status_code != 200:
                print(f"⚠️ Red Hat CVE API 조회 실패 (HTTP {response.status_code})")
                return [{"reason": f"Red Hat CVE API 조회에 실패했습니다 (HTTP {response.status_code})."}]

            all_cves = response.json()
            print(f"총 {len(all_cves)}개의 CVE 데이터를 Red Hat에서 가져왔습니다.")
            
            now = datetime.now()
            start_date = now - timedelta(days=365) # 6개월(180일)에서 1년(365일)으로 변경
            
            package_cve_map = {}
            severity_order = {"critical": 2, "important": 1, "moderate": 0, "low": -1}

            for cve in all_cves:
                public_date_str = cve.get('public_date')
                if not public_date_str: continue
                
                try:
                    cve_date = datetime.fromisoformat(public_date_str.replace('Z', '+00:00')).replace(tzinfo=None)
                except ValueError: continue
                
                severity_value = cve.get('severity')
                severity = severity_value.lower() if isinstance(severity_value, str) else 'low'

                if not (start_date <= cve_date <= now and severity in ["critical", "important"]):
                    continue
                
                cve_affected_packages = cve.get('affected_packages', [])
                for pkg_str in cve_affected_packages:
                    pkg_name_match = re.match(r'^([a-zA-Z0-9_.+-]+)-', pkg_str)
                    if pkg_name_match:
                        pkg_name = pkg_name_match.group(1)
                        if pkg_name in installed_package_names_only:
                            current_severity = severity_order.get(severity, -1)
                            existing_cve = package_cve_map.get(pkg_name)
                            
                            if not existing_cve or current_severity > severity_order.get(existing_cve.get('severity', 'low').lower(), -1):
                                cve['matched_package'] = installed_packages_map[pkg_name]
                                package_cve_map[pkg_name] = cve
            
            system_relevant_cves = list(package_cve_map.values())

            if not system_relevant_cves:
                reason = "시스템에 설치된 패키지에 직접적인 영향을 주는 최신 보안 뉴스가 없습니다."
                print(reason)
                return [{"reason": reason}]

            print(f"시스템 관련 CVE {len(system_relevant_cves)}개를 1차 선별했습니다. (패키지당 1개)")
            
            cve_identifiers = [cve['CVE'] for cve in system_relevant_cves]
            packages_str = "\n- ".join(list(installed_packages_full)[:50]) + ("..." if len(installed_packages_full) > 50 else "")

            selection_prompt = f"""
[시스템 안내]
당신은 Red Hat Enterprise Linux(RHEL)를 전문으로 다루는 '시니어 보안 위협 분석가'입니다.
당신의 임무는 주어진 RHEL 관련 보안 취약점 목록을 분석하여, 특정 시스템에 가장 시급하고 중요한 CVE를 **최대 10개**까지 선정하고, 그 선별 이유를 명확히 기록하는 것입니다.
선별 과정에서 필요하다면 **Web Search**를 활성화하여 최신 정보를 검색하고 판단에 반영하십시오.

[분석 대상 시스템 정보]
- **커널 버전:** {kernel_version}
- **설치된 패키지 목록 (일부):**
- {packages_str}

[선별 기준]
1.  **최신 동향 및 실제 위협(Web Search 활용):** Web Search를 통해 최신 보안 동향, 공개된 공격 코드(Exploit) 유무, 실제 공격(In-the-wild) 사례 등을 파악하여 위험도가 높다고 판단되는 CVE를 최우선으로 고려해야 합니다.
2.  **시스템 패키지 연관성:** 주어진 목록의 모든 CVE는 이미 시스템에 설치된 패키지와 연관성이 확인된 상태입니다.
3.  **영향받는 핵심 컴포넌트:** `kernel`, `glibc`, `openssl`, `openssh`, `systemd` 등 RHEL 시스템의 핵심 컴포넌트에 영향을 주는 취약점 severity가 (important, critical)을 우선적으로 다룹니다.

[입력 데이터]
분석 대상 CVE 목록 (시스템 관련성 확인됨): {', '.join(cve_identifiers)}

[출력 지시]
위 선별 기준을 종합적으로 적용하여 선정한 **최대 10개**의 CVE에 대한 정보를 아래 JSON 형식에 맞춰 **오직 JSON 객체만** 출력하십시오.
- `cve_id`: **반드시 [입력 데이터]에 존재하는 CVE ID 중에서만** 선택해야 합니다.
- `selection_reason`: 왜 이 CVE를 선택했는지 선별 기준(특히 웹 검색을 통해 파악한 최신 동향 및 실제 위협)에 근거하여 **한국어로 명확하고 간결하게** 기술해야 합니다.

```json
{{
  "cve_selection": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "selection_reason": "이 CVE를 선별한 구체적인 이유 (예: 최근 공격 코드가 공개되었으며, 시스템의 OpenSSL 패키지에 직접적인 영향을 줌)"
    }}
  ]
}}
```
"""
            
            selection_result = self.perform_ai_analysis(selection_prompt, is_news_request=True)
            
            top_cves_data = []
            if isinstance(selection_result, dict) and 'cve_selection' in selection_result and selection_result['cve_selection']:
                llm_log_path = self.output_dir / "llm_security_news.log"
                selected_cves_from_llm = selection_result['cve_selection']
                original_cves_map = {cve['CVE']: cve for cve in system_relevant_cves}
                
                with open(llm_log_path, 'a', encoding='utf-8') as f:
                    f.write("\n\n--- CVE SELECTION & VALIDATION ---\n")
                    for item in selected_cves_from_llm:
                        cve_id = item.get('cve_id')
                        reason = item.get('selection_reason', 'No reason provided.')
                        
                        if cve_id and cve_id in original_cves_map:
                            log_entry = f"- [VALID] {cve_id}: {reason}\n"
                            f.write(log_entry)
                            print(f"📝 로그 기록 (유효): {cve_id} 선별 이유")
                            top_cves_data.append(original_cves_map[cve_id])
                        else:
                            log_entry = f"- [INVALID/HALLUCINATED] ID: {cve_id}, Reason: {reason}\n"
                            f.write(log_entry)
                            print(f"⚠️ 경고: AI가 생성한 유효하지 않은 CVE ID({cve_id})를 무시합니다.")
            
            if not top_cves_data:
                print("⚠️ LLM이 중요 CVE를 선정하지 못했습니다. 수동으로 상위 CVE를 선택합니다.")
                top_cves_data = sorted(system_relevant_cves, key=lambda x: (severity_order.get(x.get('severity', 'low').lower(), -1), x.get('public_date')), reverse=True)[:10]

            if len(top_cves_data) < 10:
                print(f"AI가 {len(top_cves_data)}개의 CVE만 선정했습니다. 목록을 보충합니다.")
                selected_cve_ids = {cve['CVE'] for cve in top_cves_data}
                remaining_cves = [cve for cve in system_relevant_cves if cve['CVE'] not in selected_cve_ids]
                
                sorted_remaining = sorted(remaining_cves, key=lambda x: (severity_order.get(x.get('severity', 'low').lower(), -1), x.get('public_date')), reverse=True)
                
                needed = 10 - len(top_cves_data)
                top_cves_data.extend(sorted_remaining[:needed])


            processing_data = [{"cve_id": cve['CVE'], "description": cve.get('bugzilla_description', '요약 정보 없음')} for cve in top_cves_data]

            processing_prompt = f"""
[시스템 안내]
당신은 Red Hat Enterprise Linux(RHEL) 보안 전문가입니다. 당신의 임무는 주어진 각 CVE의 영문 기술 설명을 분석하여, 시스템 관리자가 쉽게 이해할 수 있도록 핵심 내용과 시스템에 미치는 영향을 중심으로 자연스러운 한국어로 요약 및 설명하는 것입니다.

[입력 데이터]
```json
{json.dumps(processing_data, indent=2, ensure_ascii=False)}
```

[출력 지시]
아래 JSON 형식에 맞춰, 각 CVE에 대한 알기 쉬운 요약 설명을 포함하여 **오직 JSON 객체만** 출력하십시오. 단순 번역이 아닌, 위협의 본질과 잠재적 영향을 명확히 전달해야 합니다.

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

            final_cves = []
            if isinstance(processed_result, dict) and 'processed_cves' in processed_result:
                processed_map = {item['cve_id']: item for item in processed_result['processed_cves']}
                for cve_data in top_cves_data:
                    cve_id = cve_data['CVE']
                    if cve_id in processed_map:
                        processed_info = processed_map[cve_id]
                        cve_date_str = cve_data.get('public_date', '')
                        if cve_date_str:
                            try:
                                cve_data['public_date'] = datetime.fromisoformat(cve_date_str.replace('Z', '+00:00')).strftime('%y/%m/%d')
                            except ValueError: pass
                        
                        cve_data['bugzilla_description'] = processed_info.get('translated_description', cve_data['bugzilla_description'])
                        final_cves.append(cve_data)
                        print(f"✅ 보안 뉴스 처리 완료: {cve_id}")
            else:
                print("⚠️ LLM의 번역 처리에 실패했습니다. 원본 데이터로 보고서를 생성합니다.")
                final_cves = top_cves_data

            print("✅ 보안 뉴스 조회 및 처리 완료.")
            return final_cves

        except Exception as e:
            print(f"❌ 보안 뉴스 조회 중 심각한 오류 발생: {e}")
            import traceback
            traceback.print_exc()
            return [{"reason": f"보안 뉴스 조회 중 오류가 발생했습니다: {e}"}]

    def create_performance_graphs(self, perf_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, str]:
        """성능 데이터를 바탕으로 세련된 스타일의 그래프를 생성하고 base64로 인코딩하여 반환합니다."""
        if not plt:
            print("⚠️ 그래프 생성을 건너뜁니다. 'matplotlib' 라이브러리를 설치하세요.")
            return {}

        print("성능 그래프 생성 중...")
        graphs = {}
        plt.style.use('seaborn-v0_8-whitegrid')

        # --- 공통 스타일 설정 ---
        graph_style = {
            'figsize': (12, 6),
            'title_fontsize': 16,
            'label_fontsize': 12,
            'tick_rotation': 30,
            'alpha': 0.3
        }
        
        # --- CPU 그래프 ---
        if perf_data.get('cpu') and len(perf_data['cpu']) > 1:
            cpu_data = perf_data['cpu']
            timestamps = [d['timestamp'] for d in cpu_data]
            user = [d['user'] for d in cpu_data]
            system = [d['system'] for d in cpu_data]
            iowait = [d['iowait'] for d in cpu_data]
            
            fig, ax = plt.subplots(figsize=graph_style['figsize'])
            colors = ['#4C72B0', '#DD8452', '#C44E52']
            ax.stackplot(timestamps, user, system, iowait, 
                         labels=['User %', 'System %', 'I/O Wait %'], 
                         colors=colors, alpha=0.7)
            
            ax.set_title('CPU 사용률 (%)', fontsize=graph_style['title_fontsize'], weight='bold')
            ax.set_ylabel('사용률 (%)', fontsize=graph_style['label_fontsize'])
            ax.legend(loc='upper left', frameon=True, facecolor='white', framealpha=0.8)
            ax.set_ylim(0, 100)
            ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
            plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
            plt.tight_layout()
            
            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=100)
            graphs['cpu_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        # --- 메모리 그래프 ---
        if perf_data.get('memory') and len(perf_data['memory']) > 1:
            mem_data = perf_data['memory']
            timestamps = [d['timestamp'] for d in mem_data]
            mem_used = [d['memused_percent'] for d in mem_data]
            
            fig, ax = plt.subplots(figsize=graph_style['figsize'])
            color = '#C44E52'
            ax.plot(timestamps, mem_used, color=color, lw=2)
            ax.fill_between(timestamps, mem_used, color=color, alpha=graph_style['alpha'])

            ax.set_title('메모리 사용률 (%)', fontsize=graph_style['title_fontsize'], weight='bold')
            ax.set_ylabel('사용률 (%)', fontsize=graph_style['label_fontsize'])
            ax.set_ylim(0, 100)
            ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
            plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=100)
            graphs['memory_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        # --- 네트워크 그래프 ---
        if perf_data.get('network') and len(perf_data['network']) > 1:
            net_data = perf_data['network']
            timestamps = [d['timestamp'] for d in net_data]
            rxkB = [d['rxkB'] for d in net_data]
            txkB = [d['txkB'] for d in net_data]

            fig, ax = plt.subplots(figsize=graph_style['figsize'])
            rx_color, tx_color = '#55A868', '#4C72B0'
            
            ax.plot(timestamps, rxkB, color=rx_color, lw=2, label='수신 (kB/s)')
            ax.fill_between(timestamps, rxkB, color=rx_color, alpha=graph_style['alpha'])
            
            ax.plot(timestamps, txkB, color=tx_color, lw=2, label='송신 (kB/s)')
            ax.fill_between(timestamps, txkB, color=tx_color, alpha=graph_style['alpha'])

            ax.set_title('네트워크 트래픽 (kB/s)', fontsize=graph_style['title_fontsize'], weight='bold')
            ax.set_ylabel('kB/s', fontsize=graph_style['label_fontsize'])
            ax.legend(loc='upper left', frameon=True, facecolor='white', framealpha=0.8)
            ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
            plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=100)
            graphs['network_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        # --- 디스크 I/O 그래프 ---
        if perf_data.get('disk') and len(perf_data['disk']) > 1:
            disk_data = perf_data['disk']
            timestamps = [d['timestamp'] for d in disk_data]
            read_kB = [d['read_kB'] for d in disk_data]
            write_kB = [d['write_kB'] for d in disk_data]

            fig, ax = plt.subplots(figsize=graph_style['figsize'])
            read_color, write_color = '#8172B3', '#DD8452'

            ax.plot(timestamps, read_kB, color=read_color, lw=2, label='읽기 (kB/s)')
            ax.fill_between(timestamps, read_kB, color=read_color, alpha=graph_style['alpha'])
            
            ax.plot(timestamps, write_kB, color=write_color, lw=2, label='쓰기 (kB/s)')
            ax.fill_between(timestamps, write_kB, color=write_color, alpha=graph_style['alpha'])

            ax.set_title('디스크 I/O (kB/s)', fontsize=graph_style['title_fontsize'], weight='bold')
            ax.set_ylabel('kB/s', fontsize=graph_style['label_fontsize'])
            ax.legend(loc='upper left', frameon=True, facecolor='white', framealpha=0.8)
            ax.xaxis.set_major_locator(mticker.MaxNLocator(nbins=10, prune='both'))
            plt.xticks(rotation=graph_style['tick_rotation'], ha='right')
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format='png', dpi=100)
            graphs['disk_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        print("✅ 성능 그래프 생성 완료.")
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
        network_details = sos_data.get('network_details', {})
        storage_info = sos_data.get('storage', [])
        process_stats = sos_data.get('process_stats', {})
        failed_services = sos_data.get('failed_services', [])
        security_news = sos_data.get('security_news', [])

        status_colors = {"정상": "#28a745", "주의": "#ffc107", "위험": "#dc3545"}
        status_color = status_colors.get(status, "#6c757d")

        ip4_details_rows = ""
        if not ip4_details:
            ip4_details_rows = "<tr><td colspan='6' style='text-align:center;'>데이터 없음</td></tr>"
        else:
            for item in ip4_details:
                state_val = item.get('state', 'unknown').lower()
                if 'up' in state_val:
                    state_html = '<td style="color: green; font-weight: bold;">🔛 UP</td>'
                elif 'down' in state_val:
                    state_html = '<td style="color: grey;">📴 DOWN</td>'
                else:
                    state_html = f"<td>❓ {html.escape(state_val.upper())}</td>"
                
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

        def create_table_rows(data_list, headers):
            rows = ""
            if not data_list:
                return f"<tr><td colspan='{len(headers)}' style='text-align:center;'>데이터 없음</td></tr>"
            
            if isinstance(data_list, list) and len(data_list) == 1 and 'reason' in data_list[0]:
                reason_text = html.escape(data_list[0]['reason'])
                return f"<tr><td colspan='{len(headers)}' style='text-align:center;'>{reason_text}</td></tr>"

            for item in data_list:
                rows += "<tr>"
                for header in headers:
                    if header == 'CVE' and isinstance(item.get(header), str):
                        cve_id = html.escape(item.get(header))
                        rows += f'<td><a href="https://access.redhat.com/security/cve/{cve_id}" target="_blank">{cve_id}</a></td>'
                    else:
                        rows += f"<td>{html.escape(str(item.get(header, 'N/A')))}</td>"
                rows += "</tr>"
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

                severity_html = ''
                if severity == 'critical':
                    severity_html = f'<td style="text-align:center;"><div class="tooltip" style="font-size: 1.5em;">🔥<span class="tooltiptext">패키지: {matched_package}</span></div></td>'
                elif severity == 'important':
                    severity_html = f'<td style="text-align:center;"><div class="tooltip" style="font-size: 1.5em;">⚠️<span class="tooltiptext">패키지: {matched_package}</span></div></td>'
                else:
                    severity_html = f"<td>{html.escape(item.get('severity', 'N/A'))}</td>"

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
                priority = html.escape(str(item.get('priority', 'N/A')))
                category = html.escape(str(item.get('category', 'N/A')))
                issue = html.escape(str(item.get('issue', 'N/A')))
                solution = html.escape(str(item.get('solution', 'N/A')))
                related_logs = item.get('related_logs', [])

                issue_html = issue
                if related_logs:
                    logs_html = html.escape('\n'.join(related_logs))
                    issue_html += f"""
                        <div class="tooltip">
                            <span class="log-icon">💬</span>
                            <span class="tooltiptext">{logs_html}</span>
                        </div>
                    """

                rows += f"""
                    <tr>
                        <td>{priority}</td>
                        <td>{category}</td>
                        <td>{issue_html}</td>
                        <td>{solution}</td>
                    </tr>
                """
            return rows

        def create_list_table(items: List[str], empty_message: str) -> str:
            if not items:
                return f"<tr><td style='text-align:center;'>{html.escape(empty_message)}</td></tr>"
            
            rows = ""
            for item in items:
                rows += f"<tr><td>{html.escape(item)}</td></tr>"
            return rows

        graph_html = ""
        if graphs:
            graph_html += '<div class="section"><h2>📊 성능 분석 그래프</h2>'
            graph_items = {
                'cpu_graph': 'CPU 사용률', 'memory_graph': '메모리 사용률',
                'network_graph': '네트워크 트래픽', 'disk_graph': '디스크 I/O'
            }
            for key, title in graph_items.items():
                if key in graphs:
                    graph_html += f'<div class="graph-container"><h3>{title}</h3><img src="data:image/png;base64,{graphs[key]}" alt="{title} Graph"></div>'
            graph_html += '</div>'
        
        netdev_rx_rows = ""
        netdev_tx_rows = ""
        netdev_data = network_details.get('netdev', [])
        for dev in netdev_data:
            rx_packets = dev.get('rx_packets', 0)
            rx_drop = dev.get('rx_drop', 0)
            rx_multicast = dev.get('rx_multicast', 0)
            rx_drop_pct = f"({int(rx_drop * 100 / rx_packets)}%)" if rx_packets > 0 else ""
            rx_multicast_pct = f"({int(rx_multicast * 100 / rx_packets)}%)" if rx_packets > 0 else ""
            netdev_rx_rows += f"<tr><td>{html.escape(dev['iface'])}</td><td>{dev['rx_bytes']:,}</td><td>{dev['rx_packets']:,}</td><td>{dev['rx_errs']}</td><td>{dev['rx_drop']} {rx_drop_pct}</td><td>{dev['rx_multicast']} {rx_multicast_pct}</td></tr>"
            netdev_tx_rows += f"<tr><td>{html.escape(dev['iface'])}</td><td>{dev['tx_bytes']:,}</td><td>{dev['tx_packets']:,}</td><td>{dev['tx_errs']}</td><td>{dev['tx_drop']}</td><td>{dev['tx_colls']}</td><td>{dev['tx_carrier']}</td></tr>"

        ethtool_rows = ""
        ethtool_data = network_details.get('ethtool', {})
        for iface, data in ethtool_data.items():
            ethtool_rows += f"<tr><td>{html.escape(iface)}</td><td>{html.escape(data.get('link', 'N/A'))}</td><td>{html.escape(data.get('speed', 'N/A'))}</td><td>{html.escape(data.get('driver', 'N/A'))}</td><td>{html.escape(data.get('firmware', 'N/A'))}</td></tr>"

        failed_services_rows = create_list_table(failed_services, "실패한 서비스가 없습니다.")
        critical_issues_rows = create_list_table(critical_issues, "발견된 심각한 이슈가 없습니다.")
        warnings_rows = create_list_table(warnings, "특별한 경고 사항이 없습니다.")

        html_template = f"""
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI 분석 보고서</title>
    <style>
        @import url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts_six@1.2/S-CoreDream.css');
        body {{ font-family: 'S-CoreDream', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f7f9; color: #333; margin: 0; padding: 20px; }}
        .container {{ max-width: 1200px; margin: auto; background: #fff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); overflow: hidden; }}
        header {{ background-color: #343a40; color: white; padding: 20px; text-align: center; }}
        header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 20px; }}
        .section {{ margin-bottom: 25px; }}
        .section h2 {{ 
            font-size: 20px;
            border-left: 5px solid #007bff; 
            padding-left: 10px; 
            margin-bottom: 15px; 
            color: #343a40; 
        }}
        .graph-container {{
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            background-color: #fafafa;
        }}
        .graph-container h3 {{ text-align: center; margin-top: 0; color: #333; }}
        .graph-container img {{
            width: 100%;
            max-width: 900px;
            display: block;
            margin: auto;
            border-radius: 4px;
        }}
        .data-table {{
            width: 100%; border-collapse: collapse; margin-bottom: 20px;
            table-layout: fixed; font-size: 14px; line-height: 1.6;
        }}
        .data-table th, .data-table td {{
            border: 1px solid #dee2e6; padding: 12px; text-align: left;
            word-wrap: break-word; vertical-align: top;
        }}
        .data-table thead th {{
            background-color: #f8f9fa; color: #495057; font-weight: 600;
            border-bottom: 2px solid #dee2e6;
        }}
        .data-table tbody th {{ background-color: #f8f9fa; font-weight: 600; width: 25%; }}
        .data-table tbody tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .data-table tbody tr:hover {{ background-color: #e9ecef; }}
        .ai-status {{ font-size: 1.2em; font-weight: bold; color: {status_color}; }}
        footer {{ text-align: center; padding: 15px; font-size: 12px; color: #888; background-color: #f4f7f9; }}
        
        .tooltip {{ position: relative; display: inline-block; cursor: pointer; }}
        .tooltip .tooltiptext {{
            visibility: hidden; width: 450px; max-height: 250px; overflow-y: auto; background-color: #333; color: #fff; text-align: left;
            border-radius: 6px; padding: 10px; position: absolute; z-index: 1; bottom: 125%;
            left: 50%; margin-left: -225px; opacity: 0; transition: opacity 0.3s; font-size: 12px;
            white-space: pre-wrap; word-break: break-all; box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            font-family: 'Consolas', 'Monaco', monospace;
        }}
        .tooltip .tooltiptext::after {{
            content: ""; position: absolute; top: 100%; left: 50%; margin-left: -5px;
            border-width: 5px; border-style: solid; border-color: #333 transparent transparent transparent;
        }}
        .tooltip:hover .tooltiptext {{ visibility: visible; opacity: 1; }}
        .log-icon {{ font-size: 14px; margin-left: 5px; color: #007bff; }}
    </style>
</head>
<body>
    <div class="container">
        <header><h1>S-Core System Report</h1></header>
        <div class="content">
            
            <div class="section">
                <h2>ℹ️ 시스템 요약</h2>
                <table class="data-table">
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
                <table class="data-table">
                    <thead><tr><th>Interface</th><th>Master IF</th><th>MAC Address</th><th>MTU</th><th>State</th><th>IPv4 Address</th></tr></thead>
                    <tbody>{ip4_details_rows}</tbody>
                </table>
                <h3>라우팅 테이블</h3>
                <table class="data-table">
                    <thead><tr><th>Destination</th><th>Gateway</th><th>Device</th><th>Source</th></tr></thead>
                    <tbody>{create_table_rows(system_info.get('routing_table', []), ['destination', 'gateway', 'device', 'source'])}</tbody>
                </table>
                <h3>ETHTOOL 상태</h3>
                <table class="data-table">
                    <thead><tr><th>Interface</th><th>Link</th><th>Speed</th><th>Driver</th><th>Firmware</th></tr></thead>
                    <tbody>{ethtool_rows}</tbody>
                </table>
                <h3>NETDEV 통계 (Receive)</h3>
                <table class="data-table">
                    <thead><tr><th>Interface</th><th>RxBytes</th><th>RxPackets</th><th>RxErrs</th><th>RxDrop</th><th>RxMulticast</th></tr></thead>
                    <tbody>{netdev_rx_rows}</tbody>
                </table>
                <h3>NETDEV 통계 (Transmit)</h3>
                <table class="data-table">
                    <thead><tr><th>Interface</th><th>TxBytes</th><th>TxPackets</th><th>TxErrs</th><th>TxDrop</th><th>TxColls</th><th>TxCarrier</th></tr></thead>
                    <tbody>{netdev_tx_rows}</tbody>
                </table>
                <h3>소켓 통계</h3>
                <pre style="background:#eee; padding:10px; border-radius:4px; word-wrap:break-word;">{html.escape(chr(10).join(network_details.get('sockstat', [])))}</pre>
                <h3>네트워크 본딩</h3>
                <table class="data-table">
                    <thead><tr><th>Device</th><th>Mode</th><th>Slaves</th></tr></thead>
                    <tbody>{create_table_rows(network_details.get('bonding', []), ['device', 'mode', 'slaves'])}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>💾 스토리지 및 파일 시스템</h2>
                <table class="data-table">
                    <thead><tr><th>Filesystem</th><th>Size</th><th>Used</th><th>Avail</th><th>Use%</th><th>Mounted on</th></tr></thead>
                    <tbody>{create_table_rows(storage_info, ['filesystem', 'size', 'used', 'avail', 'use%', 'mounted_on'])}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>⚙️ 리소스 사용 현황</h2>
                <h3>프로세스 요약</h3>
                <table class="data-table">
                    <tbody><tr><th>Total Processes</th><td>{process_stats.get('total', 'N/A')}</td></tr></tbody>
                </table>
                <h3>Top Users of CPU & MEM</h3>
                <table class="data-table">
                    <thead><tr><th>USER</th><th>%CPU</th><th>%MEM</th><th>RSS</th></tr></thead>
                    <tbody>{create_table_rows(process_stats.get('by_user', []), ['user', 'cpu%', 'mem%', 'rss'])}</tbody>
                </table>
                <h3>Uninterruptible Sleep Processes ({len(process_stats.get('uninterruptible', []))})</h3>
                <table class="data-table">
                    <thead><tr><th>USER</th><th>PID</th><th>%CPU</th><th>%MEM</th><th>RSS</th><th>STAT</th><th>START</th><th>TIME</th><th>COMMAND</th></tr></thead>
                    <tbody>{create_table_rows(process_stats.get('uninterruptible', []), ['user', 'pid', 'cpu%', 'mem%', 'rss', 'stat', 'start', 'time', 'command'])}</tbody>
                </table>
                <h3>Zombie Processes ({len(process_stats.get('zombie', []))})</h3>
                <table class="data-table">
                    <thead><tr><th>USER</th><th>PID</th><th>%CPU</th><th>%MEM</th><th>RSS</th><th>STAT</th><th>START</th><th>TIME</th><th>COMMAND</th></tr></thead>
                    <tbody>{create_table_rows(process_stats.get('zombie', []), ['user', 'pid', 'cpu%', 'mem%', 'rss', 'stat', 'start', 'time', 'command'])}</tbody>
                </table>
                <h3>Top 5 Processes (CPU)</h3>
                <table class="data-table">
                    <colgroup><col style="width:10%"><col style="width:15%"><col style="width:15%"><col style="width:60%"></colgroup>
                    <thead><tr><th>PID</th><th>User</th><th>CPU %</th><th>Command</th></tr></thead>
                    <tbody>{create_table_rows(process_stats.get('top_cpu', []), ['pid', 'user', 'cpu%', 'command'])}</tbody>
                </table>
                <h3>Top 5 Processes (Memory)</h3>
                <table class="data-table">
                    <colgroup><col style="width:10%"><col style="width:15%"><col style="width:15%"><col style="width:60%"></colgroup>
                    <thead><tr><th>PID</th><th>User</th><th>RSS (KiB)</th><th>Command</th></tr></thead>
                    <tbody>{create_table_rows(process_stats.get('top_mem', []), ['pid', 'user', 'rss', 'command'])}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>🔧 실패한 서비스 ({len(failed_services)}개)</h2>
                <table class="data-table">
                    <colgroup><col style="width:100%"></colgroup>
                    <thead><tr><th>상세 내용</th></tr></thead>
                    <tbody>{failed_services_rows}</tbody>
                </table>
            </div>

            <div class="section">
                <h2>🚨 AI 분석: 심각한 이슈 ({len(critical_issues)}개)</h2>
                <table class="data-table">
                    <colgroup><col style="width:100%"></colgroup>
                    <thead><tr><th>상세 내용</th></tr></thead>
                    <tbody>{critical_issues_rows}</tbody>
                </table>
            </div>

            <div class="section">
                <h2>⚠️ AI 분석: 경고 사항 ({len(warnings)}개)</h2>
                <table class="data-table">
                    <colgroup><col style="width:100%"></colgroup>
                    <thead><tr><th>상세 내용</th></tr></thead>
                    <tbody>{warnings_rows}</tbody>
                </table>
            </div>

            <div class="section">
                <h2>💡 AI 분석: 권장사항 ({len(recommendations)}개)</h2>
                <table class="data-table">
                    <colgroup><col style="width:10%"><col style="width:15%"><col style="width:35%"><col style="width:40%"></colgroup>
                    <thead><tr><th>우선순위</th><th>카테고리</th><th>문제점 💬</th><th>해결 방안</th></tr></thead>
                    <tbody>{create_recommendation_rows(recommendations)}</tbody>
                </table>
            </div>
            
            <div class="section">
                <h2>🤖 AI 종합 분석</h2>
                <table class="data-table">
                    <colgroup><col style="width:20%"><col style="width:80%"></colgroup>
                    <tbody>
                        <tr><th>종합 상태</th><td><span class="ai-status">{status}</span></td></tr>
                        <tr><th>건강도 점수</th><td>{score}/100</td></tr>
                        <tr><th>요약</th><td>{summary}</td></tr>
                    </tbody>
                </table>
            </div>

            <div class="section">
                <h2>🛡️ 보안 뉴스 (가장 중요한 CVE 최대 10개) <span style="font-size: 0.7em; font-weight: normal;">(🔥 Critical, ⚠️ Important)</span></h2>
                <table class="data-table">
                    <colgroup><col style="width:18%"><col style="width:10%"><col style="width:12%"><col style="width:60%"></colgroup>
                    <thead><tr><th>CVE 식별자</th><th>심각도</th><th>생성일</th><th>위협 및 영향 요약</th></tr></thead>
                    <tbody>{create_security_news_rows(security_news)}</tbody>
                </table>
                <p style="font-size: 12px; text-align: center;">보안 정보에 대한 상세 내용은 <a href="https://access.redhat.com/security/security-updates/security-advisories" target="_blank">Red Hat Security Advisories</a> 사이트에서 확인하실 수 있습니다.</p>
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
    print(f"압축 파일 해제 중: {archive_path}")
    try:
        with tarfile.open(archive_path, 'r:*') as tar:
            if sys.platform == "win32":
                tar.extractall(path=extract_dir, filter=win_safe_filter)
            else:
                tar.extractall(path=extract_dir)
        print(f"✅ 압축 해제 완료: {extract_dir}")
        return extract_dir
    except tarfile.TarError as e:
        raise Exception(f"압축 파일 해제 실패: {e}")

def rmtree_onerror(func, path, exc_info):
    if isinstance(exc_info[1], PermissionError):
        try:
            os.chmod(path, 0o777)
            func(path)
        except Exception as e:
            print(f"onerror 핸들러에서도 파일 처리 실패: {path}, 오류: {e}")

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
    api_token = args.api_token or os.getenv('LLM_API_TOKEN')
    
    if not plt:
        print("경고: 'matplotlib' 라이브러리를 찾을 수 없어 그래프 생성 기능이 비활성화됩니다.", file=sys.stderr)
        print("'pip install matplotlib' 명령어로 설치해주세요.", file=sys.stderr)
    
    if not BeautifulSoup:
        print("경고: 'beautifulsoup4'와 'lxml' 라이브러리를 찾을 수 없어 XML 파싱 기능이 비활성화됩니다.", file=sys.stderr)
        print("'pip install beautifulsoup4 lxml' 명령어로 설치해주세요.", file=sys.stderr)

    analyzer = AIAnalyzer(
        llm_url=args.llm_url, model_name=args.model,
        endpoint_path=args.endpoint_path, api_token=api_token,
        output_dir=args.output
    )

    if args.list_models:
        analyzer.list_available_models()
        sys.exit(0)

    if args.test_only:
        if not args.model: parser.error("--test-only 옵션은 --model 인자가 필요합니다.")
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
    
    temp_extract_dir = Path(args.output) / f"temp_{Path(args.sosreport_archive).stem}_{int(time.time())}"
    
    try:
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
        graphs = analyzer.create_performance_graphs(sos_data.get("performance_data", {}))
        
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
        sys.exit(1)
    finally:
        if os.path.exists(temp_extract_dir):
            print(f"임시 디렉토리 정리: {temp_extract_dir}")
            try:
                shutil.rmtree(temp_extract_dir, onerror=rmtree_onerror)
                print("✅ 임시 디렉토리 정리 완료.")
            except Exception as e:
                print(f"❌ 임시 디렉토리 정리에 최종 실패했습니다: {e}. 수동으로 삭제해주세요: {temp_extract_dir}")

if __name__ == "__main__":
    main()
