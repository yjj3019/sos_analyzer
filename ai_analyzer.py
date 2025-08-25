#!/usr/bin/env python3
"""
sosreport 압축 파일 AI 분석 및 보고서 생성 모듈
sosreport 압축 파일을 입력받아 압축 해제, 데이터 추출, AI 분석, HTML 보고서 생성을 한 번에 수행합니다.

사용법:
    # 기본 사용법 (sosreport 압축 파일을 입력)
    python3 ai_analyzer.py sosreport-archive.tar.xz --llm-url <URL> --model <MODEL> --api-token <TOKEN>

    # 사용 가능한 모델 목록 확인
    python3 ai_analyzer.py --llm-url <URL> --api-token <TOKEN> --list-models
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

# --- 그래프 생성을 위한 라이브러리 ---
# "pip install matplotlib" 명령어로 설치 필요
try:
    import matplotlib
    matplotlib.use('Agg') # GUI 백엔드 없이 실행하기 위한 설정
    import matplotlib.pyplot as plt
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

    def _parse_system_details(self) -> Dict[str, Any]:
        """xsos 스타일의 상세 시스템 정보를 파싱합니다."""
        details = {}
        details['hostname'] = self._read_file(['hostname', 'sos_commands/general/hostname', 'proc/sys/kernel/hostname'])
        details['os_version'] = self._read_file(['etc/redhat-release'])
        uname_content = self._read_file(['uname', 'sos_commands/kernel/uname_-a'])
        details['kernel'] = uname_content.split('\n')[0]
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
        details['uptime'] = self._read_file(['uptime', 'sos_commands/general/uptime', 'sos_commands/host/uptime'])
        
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
        """df -h 출력에서 파일 시스템 사용량을 파싱합니다."""
        df_content = self._read_file(['df', 'sos_commands/filesys/df_-alPh'])
        filesystems = []
        for line in df_content.split('\n')[1:]:
            parts = line.split()
            if len(parts) >= 6 and parts[0].startswith('/'):
                filesystems.append({'filesystem': parts[0], 'size': parts[1], 'used': parts[2], 'avail': parts[3], 'use%': parts[4], 'mounted_on': parts[5]})
        return filesystems

    def _parse_process_stats(self) -> Dict[str, Any]:
        """ps 명령어 출력에서 프로세스 관련 통계를 파싱합니다."""
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
        """systemctl list-units 출력에서 실패한 서비스를 파싱합니다."""
        systemctl_content = self._read_file(['sos_commands/systemd/systemctl_list-units_--all'])
        failed_services = []
        for line in systemctl_content.split('\n'):
            if 'failed' in line:
                parts = line.strip().split()
                if len(parts) >= 4:
                    failed_services.append(f"{parts[0]} - {' '.join(parts[1:4])}")
        return failed_services

    def _parse_ip4_details(self) -> List[Dict[str, str]]:
        """ip addr 명령어 출력에서 상세 인터페이스 정보를 파싱합니다."""
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
        """NETDEV, SOCKSTAT, BONDING, ETHTOOL 정보를 파싱합니다."""
        details = {'netdev': [], 'sockstat': [], 'bonding': [], 'ethtool': {}}

        # NETDEV from /proc/net/dev
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

        # SOCKSTAT from /proc/net/sockstat
        sockstat_content = self._read_file(['proc/net/sockstat'])
        details['sockstat'] = sockstat_content.split('\n')

        # BONDING from /proc/net/bonding/*
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
        
        # ETHTOOL from sos_commands/networking/ethtool_*
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
        """라우팅 테이블 정보를 파싱하고 불필요한 항목을 필터링합니다."""
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

            if route_info['source'].startswith('127.'):
                continue
            
            if route_info['destination'].lower() != 'default' and route_info['source'] == '-':
                continue
            
            routes.append(route_info)
        return routes

    def _parse_sar_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """sar 명령어 출력 결과에서 성능 데이터를 파싱합니다."""
        content = ""
        sa_dir = self.base_path / 'var/log/sa'
        if sa_dir.is_dir():
            sar_files = sorted([f for f in sa_dir.iterdir() if f.name.startswith('sar') and f.is_file()])
            if sar_files:
                for file_path in sar_files: content += file_path.read_text(encoding='utf-8', errors='ignore') + "\n"
        
        if not content.strip():
            content = self._read_file(['sos_commands/monitoring/sar_-A'])

        if not content.strip(): return {}
        print("sar 성능 데이터 파싱 중...")
        performance_data = {'cpu': [], 'memory': [], 'network': []}

        cpu_section = re.search(r'(\d{2}:\d{2}:\d{2}\s+CPU\s+%user\s+%nice\s+%system\s+%iowait\s+%steal\s+%idle\n(?:.*\n)+?)\n\n', content, re.MULTILINE)
        if cpu_section:
            for line in cpu_section.group(1).strip().split('\n'):
                parts = line.split()
                if len(parts) >= 8 and parts[1] == 'all':
                    performance_data['cpu'].append({'timestamp': parts[0], 'user': float(parts[2]), 'system': float(parts[4]), 'idle': float(parts[7])})

        mem_section = re.search(r'(\d{2}:\d{2}:\d{2}\s+kbmemfree\s+kbmemused\s+%memused\s+kbbuffers\s+kbcached\s+kbcommit\s+%commit\n(?:.*\n)+?)\n\n', content, re.MULTILINE)
        if mem_section:
            for line in mem_section.group(1).strip().split('\n'):
                parts = line.split()
                if len(parts) >= 4 and parts[0].count(':') == 2:
                    performance_data['memory'].append({'timestamp': parts[0], 'memused_percent': float(parts[3])})

        net_section = re.search(r'(\d{2}:\d{2}:\d{2}\s+IFACE\s+rxpck/s\s+txpck/s\s+rxkB/s\s+txkB/s\s+rxcmp/s\s+txcmp/s\s+rxmcst/s\n(?:.*\n)+?)\n\n', content, re.MULTILINE)
        if net_section:
            net_agg = {}
            for line in net_section.group(1).strip().split('\n'):
                parts = line.split()
                if len(parts) >= 6 and parts[1] not in ('IFACE', 'lo'):
                    ts = parts[0]
                    if ts not in net_agg: net_agg[ts] = {'rxkB': 0.0, 'txkB': 0.0}
                    net_agg[ts]['rxkB'] += float(parts[4])
                    net_agg[ts]['txkB'] += float(parts[5])
            for ts, data in net_agg.items():
                performance_data['network'].append({'timestamp': ts, **data})

        print("✅ sar 성능 데이터 파싱 완료.")
        return performance_data

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

        print("AI 분석기 초기화 완료")
        print(f"LLM 기본 URL: {self.llm_url}")
        if self.model_name:
            print(f"사용 모델: {self.model_name}")

    def list_available_models(self):
        """서버에서 사용 가능한 모델 목록을 조회하고 출력합니다."""
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
        """LLM 서비스 상태 확인"""
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
        """LLM 연결 테스트"""
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
        """AI 분석 수행. 실패 시 예외 발생."""
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
                # 'a' (append) mode to keep logs from multiple calls
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
        """AI 분석을 위한 프롬프트 생성"""
        print("AI 분석 프롬프트 생성 중...")
        
        data_str = json.dumps({
            "system_info": sosreport_data.get("system_info"),
            "storage": sosreport_data.get("storage"),
            "failed_services": sosreport_data.get("failed_services"),
            "process_stats_summary": {
                "total": sosreport_data.get("process_stats", {}).get("total"),
                "zombie_count": len(sosreport_data.get("process_stats", {}).get("zombie", [])),
            }
        }, indent=2, ensure_ascii=False)

        prompt = f"""당신은 Red Hat Enterprise Linux 시스템 전문가입니다. 다음 sosreport 분석 데이터를 종합적으로 검토하고 전문적인 진단을 제공해주세요.

## 분석 데이터
```json
{data_str}
```

## 분석 요청
위 데이터를 바탕으로 다음 JSON 형식에 맞춰 종합적인 시스템 분석을 제공해주세요.

```json
{{
  "system_status": "정상|주의|위험",
  "overall_health_score": 100,
  "critical_issues": ["발견된 심각한 문제들의 구체적인 설명"],
  "warnings": ["주의가 필요한 사항들"],
  "recommendations": [
    {{
      "priority": "높음|중간|낮음",
      "category": "성능|보안|안정성|유지보수",
      "issue": "문제점 설명",
      "solution": "구체적인 해결 방안"
    }}
  ],
  "summary": "전체적인 시스템 상태와 주요 권장사항에 대한 종합 요약"
}}
```

**중요**: 당신의 응답은 반드시 위 JSON 형식이어야 합니다. 다른 설명이나 텍스트 없이, `{{`로 시작해서 `}}`로 끝나는 순수한 JSON 객체만 출력해야 합니다.
"""
        return prompt

    def _parse_ai_response(self, ai_response: str) -> Any:
        """AI 응답에서 JSON 추출 및 파싱. 실패 시 예외 발생."""
        print("AI 응답 파싱 중...")
        
        if not ai_response or not ai_response.strip():
            raise ValueError("AI 응답이 비어 있습니다.")

        # LLM의 거절 메시지 패턴 확인
        refusal_patterns = [
            "i'm sorry", "i cannot", "i can't", "i am unable", 
            "죄송합니다", "할 수 없습니다"
        ]
        # 응답을 소문자로 변환하여 패턴 검사
        if any(pattern in ai_response.lower() for pattern in refusal_patterns):
            raise ValueError(f"LLM이 요청 처리를 거부했습니다. (응답: '{ai_response.strip()}')")

        try:
            # 마크다운 코드 블록과 앞뒤 공백을 제거
            cleaned_response = re.sub(r'^```(json)?\s*|\s*```$', '', ai_response.strip())
            
            # JSON 객체가 시작하고 끝나는 부분을 명시적으로 찾음
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
            # 여기서 발생하는 ValueError는 JSON 객체 못찾는 경우 포함
            error_message = f"AI 응답 처리 중 오류 발생: {e}.\n--- 원본 응답 ---\n{ai_response}\n----------------"
            print(error_message)
            raise ValueError(error_message)

    def fetch_security_news(self) -> List[Dict[str, str]]:
        """RHEL 관련 최신 보안 뉴스를 가져옵니다."""
        print("최신 RHEL 보안 뉴스 조회 중 (Red Hat API 직접 호출)...")
        try:
            # 1. Red Hat의 공식 CVE 데이터 API를 직접 호출
            api_url = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
            print(f"Red Hat CVE API 호출: {api_url}")
            response = requests.get(api_url, timeout=120)
            if response.status_code != 200:
                print(f"⚠️ Red Hat CVE API 조회 실패 (HTTP {response.status_code}), 보안 뉴스 조회를 건너뜁니다.")
                return []

            all_cves = response.json()
            print(f"총 {len(all_cves)}개의 CVE 데이터를 가져왔습니다.")
            
            # 2. 데이터 필터링 (미래 CVE 제외, 최근 180일, Critical/Important 등급)
            now = datetime.now()
            start_date = now - timedelta(days=180)
            
            filtered_cves = []
            for cve in all_cves:
                public_date_str = cve.get('public_date')
                if not public_date_str:
                    continue
                
                try:
                    cve_date = datetime.fromisoformat(public_date_str.replace('Z', '+00:00')).replace(tzinfo=None)
                except ValueError:
                    print(f"경고: 잘못된 날짜 형식으로 CVE를 건너뜁니다: {cve.get('CVE')}, {public_date_str}")
                    continue

                if (cve_date <= now and 
                    cve_date >= start_date and 
                    isinstance(cve.get('severity'), str) and 
                    cve.get('severity').lower() in ["critical", "important"]):
                    filtered_cves.append(cve)

            print(f"필터링 후: {len(filtered_cves)}개 CVE")

            if not filtered_cves:
                print("분석할 최신 보안 뉴스가 없습니다.")
                return []
            
            # 3. [1단계 AI 분석] 가장 중요한 CVE 5개 선정
            cve_identifiers = [cve['CVE'] for cve in filtered_cves]
            selection_prompt = f"""[시스템 안내]  
당신은 보안 전문가이자 리눅스 엔지니어입니다.  
다음 조건에 맞춰 최근 6개월 내 전 세계적으로 이슈된 보안 취약점 중 Red Hat Enterprise Linux(RHEL) 관련 내용을 조사하고 요약하세요.  

[조사 및 선별 조건]  
1. 출처는 반드시 Red Hat 공식 보안 자료(예: Red Hat Security Advisories, Red Hat CVE 데이터베이스) 기반으로 하며, RHEL 외 다른 리눅스 배포판(Ubuntu, Debian 등)은 제외합니다.  
2. 중요도는 Important 또는 Critical 등급의 취약점에 한정합니다.  
3. 우선순위는 "kernel, glibc, openssl, openssh, systemd" 관련 취약점으로 하며, 이 중 5개를 무작위로 선별합니다.  
4. 선별된 취약점은 Red Hat 공식 사이트 및 신뢰할 수 있는 보안 사이트(cve.mitre.org, nvd.nist.gov)에서 검증 후, RHEL 환경에서의 영향과 대응 현황을 중심으로 간략히 요약합니다.  
   - 기술적 세부사항보다는 보안 커뮤니티 논의, 주요 기업 반응, 패치 상태 위주로 작성합니다.  
5. 필요시 "Web Search" 기능을 활성화하여 최신 정보와 추가 의견을 확보하세요.  

[출력 형식 예시]  
- CVE 번호 및 취약점명  
- 영향받는 컴포넌트 및 RHEL 버전  
- 취약점 중요도  
- 보안 커뮤니티 및 기업 반응 요약  
- 현재 패치 및 대응 현황  

현재 날짜: 준수

위 조건을 엄격히 준수하여 조사 및 요약을 시작하세요.

CVE 목록: {', '.join(cve_identifiers)}
응답은 반드시 다음 JSON 형식이어야 해. 가장 중요한 5개의 CVE에 대한 분석만 객체로 포함해야 해.
```json
{{
  "cve_trends": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "component": "kernel",
      "summary": "설명 최소화 (논의, 반응, 패치 현황 중심)",
      "red_hat_advisory": "RHSA-XXXX:XXXX 또는 해당 링크"
    }}
  ]
}}
```
다른 설명 없이 순수한 JSON 객체만 출력해야 합니다."""
            
            selection_result = self.perform_ai_analysis(selection_prompt, is_news_request=True)
            
            if not (isinstance(selection_result, dict) and 'cve_trends' in selection_result and selection_result['cve_trends']):
                print("⚠️ LLM이 중요 CVE를 선정하지 못했습니다.")
                return []

            trends_map = {item['cve_id']: item['summary'] for item in selection_result['cve_trends']}
            selected_cve_ids = trends_map.keys()

            # 원본 데이터에서 선택된 CVE 정보만 추출
            top_cves_data = [cve for cve in filtered_cves if cve['CVE'] in selected_cve_ids]

            # 4. [2단계 AI 분석] 요약 번역 및 동향 재요약
            processing_data = []
            for cve in top_cves_data:
                processing_data.append({
                    "cve_id": cve['CVE'],
                    "description": cve.get('bugzilla_description', '요약 정보 없음'),
                    "trend": trends_map.get(cve['CVE'], '')
                })

            processing_prompt = f"""다음 JSON 데이터에 포함된 각 CVE에 대해, 'description'을 한국어로 번역하고 'trend'를 한 문장으로 더 간결하게 요약해줘.
입력 데이터:
```json
{json.dumps(processing_data, indent=2, ensure_ascii=False)}
```
응답은 반드시 다음 JSON 형식이어야 해:
```json
{{
  "processed_cves": [
    {{
      "cve_id": "CVE-XXXX-XXXX",
      "translated_description": "한국어로 번역된 요약",
      "concise_trend": "한 문장으로 요약된 동향"
    }}
  ]
}}
```
다른 설명 없이 순수한 JSON 객체만 출력해야 합니다."""

            processed_result = self.perform_ai_analysis(processing_prompt, is_news_request=True)

            # 5. 최종 데이터 조합
            final_cves = []
            if isinstance(processed_result, dict) and 'processed_cves' in processed_result:
                processed_map = {item['cve_id']: item for item in processed_result['processed_cves']}
                for cve_data in top_cves_data:
                    cve_id = cve_data['CVE']
                    if cve_id in processed_map:
                        processed_info = processed_map[cve_id]
                        # 날짜 형식 변경
                        cve_date_str = cve_data.get('public_date', '')
                        if cve_date_str:
                            try:
                                # 이미 YY/MM/DD 형식일 수 있으므로 예외 처리
                                datetime.strptime(cve_date_str, '%y/%m/%d')
                            except ValueError:
                                cve_data['public_date'] = datetime.fromisoformat(cve_date_str.replace('Z', '+00:00')).strftime('%y/%m/%d')
                        
                        # 번역 및 요약된 내용으로 업데이트
                        cve_data['bugzilla_description'] = processed_info.get('translated_description', cve_data['bugzilla_description'])
                        cve_data['trends'] = processed_info.get('concise_trend', trends_map.get(cve_id, ''))
                        
                        final_cves.append(cve_data)
                        print(f"✅ 보안 뉴스 처리 완료: {cve_id}")
            else:
                print("⚠️ LLM의 번역/요약 처리에 실패했습니다. 원본 데이터로 보고서를 생성합니다.")
                return top_cves_data # 실패 시, 번역/재요약 없이 1단계 결과라도 반환

            print("✅ 보안 뉴스 조회 및 처리 완료.")
            return final_cves

        except Exception as e:
            print(f"❌ 보안 뉴스 조회 중 심각한 오류 발생: {e}")
            return []


    def create_performance_graphs(self, perf_data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, str]:
        """성능 데이터를 바탕으로 그래프를 생성하고 base64로 인코딩하여 반환합니다."""
        if not plt:
            print("⚠️ 그래프 생성을 건너뜁니다. 'matplotlib' 라이브러리를 설치하세요.")
            return {}

        print("성능 그래프 생성 중...")
        graphs = {}
        
        # CPU 그래프
        if perf_data.get('cpu'):
            cpu_data = perf_data['cpu']
            timestamps = [d['timestamp'] for d in cpu_data]
            user = [d['user'] for d in cpu_data]
            system = [d['system'] for d in cpu_data]
            idle = [d['idle'] for d in cpu_data]
            
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.stackplot(timestamps, user, system, idle, labels=['User %', 'System %', 'Idle %'], colors=['#007bff', '#ffc107', '#28a745'])
            ax.set_title('CPU Usage (%)')
            ax.set_xlabel('Time')
            ax.set_ylabel('Usage (%)')
            ax.legend(loc='upper left')
            ax.tick_params(axis='x', rotation=45)
            plt.tight_layout()
            
            buf = io.BytesIO()
            fig.savefig(buf, format='png')
            graphs['cpu_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        # 메모리 그래프
        if perf_data.get('memory'):
            mem_data = perf_data['memory']
            timestamps = [d['timestamp'] for d in mem_data]
            mem_used = [d['memused_percent'] for d in mem_data]
            
            fig, ax = plt.subplots(figsize=(10, 5))
            ax.plot(timestamps, mem_used, label='Memory Used %', color='#dc3545')
            ax.set_title('Memory Usage (%)')
            ax.set_xlabel('Time')
            ax.set_ylabel('Usage (%)')
            ax.legend(loc='upper left')
            ax.tick_params(axis='x', rotation=45)
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format='png')
            graphs['memory_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        # 네트워크 그래프
        if perf_data.get('network'):
            net_data = perf_data['network']
            timestamps = [d['timestamp'] for d in net_data]
            rxkB = [d['rxkB'] for d in net_data]
            txkB = [d['txkB'] for d in net_data]

            fig, ax = plt.subplots(figsize=(10, 5))
            ax.plot(timestamps, rxkB, label='Received (kB/s)', color='#17a2b8')
            ax.plot(timestamps, txkB, label='Transmitted (kB/s)', color='#6f42c1')
            ax.set_title('Network Traffic (kB/s)')
            ax.set_xlabel('Time')
            ax.set_ylabel('kB/s')
            ax.legend(loc='upper left')
            ax.tick_params(axis='x', rotation=45)
            plt.tight_layout()

            buf = io.BytesIO()
            fig.savefig(buf, format='png')
            graphs['network_graph'] = base64.b64encode(buf.getvalue()).decode('utf-8')
            plt.close(fig)

        print("✅ 성능 그래프 생성 완료.")
        return graphs

    def create_html_report(self, analysis_result: Dict[str, Any], sos_data: Dict[str, Any], graphs: Dict[str, str], output_dir: str, original_file: str) -> str:
        """분석 결과와 그래프를 바탕으로 HTML 보고서 생성"""
        print("HTML 보고서 생성 중...")
        
        base_name = Path(original_file).stem.replace('.tar', '')
        report_file = Path(output_dir) / f"{base_name}_report.html"

        # AI 분석 결과 추출
        status = html.escape(analysis_result.get('system_status', 'N/A'))
        score = analysis_result.get('overall_health_score', 'N/A')
        summary = html.escape(analysis_result.get('summary', '정보 없음')).replace('\n', '<br>')
        critical_issues = analysis_result.get('critical_issues', [])
        warnings = analysis_result.get('warnings', [])
        recommendations = analysis_result.get('recommendations', [])
        
        # 시스템 정보 추출
        system_info = sos_data.get('system_info', {})
        ip4_details = sos_data.get('ip4_details', [])
        network_details = sos_data.get('network_details', {})
        storage_info = sos_data.get('storage', [])
        process_stats = sos_data.get('process_stats', {})
        failed_services = sos_data.get('failed_services', [])
        security_news = sos_data.get('security_news', [])

        status_colors = {"정상": "#28a745", "주의": "#ffc107", "위험": "#dc3545"}
        status_color = status_colors.get(status, "#6c757d")

        # IP4 상세 정보 테이블 행 생성 (아이콘 및 색상 포함)
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

        # HTML 테이블 생성 함수
        def create_table_rows(data_list, headers, no_data_message="데이터 없음"):
            rows = ""
            if not data_list:
                return f"<tr><td colspan='{len(headers)}' style='text-align:center;'>{no_data_message}</td></tr>"
            for item in data_list:
                rows += "<tr>"
                for header in headers:
                    # CVE-ID를 링크로 만들기
                    if header == 'CVE' and isinstance(item.get(header), str):
                        cve_id = html.escape(item.get(header))
                        rows += f'<td><a href="https://access.redhat.com/security/cve/{cve_id}" target="_blank">{cve_id}</a></td>'
                    else:
                        rows += f"<td>{html.escape(str(item.get(header, 'N/A')))}</td>"
                rows += "</tr>"
            return rows

        # 그래프 섹션 HTML 생성
        graph_html = ""
        if graphs:
            graph_html += '<div class="section"><h2>📊 성능 분석 그래프</h2>'
            if 'cpu_graph' in graphs: graph_html += f'<h3>CPU 사용률</h3><img src="data:image/png;base64,{graphs["cpu_graph"]}" alt="CPU Graph" style="width:100%;">'
            if 'memory_graph' in graphs: graph_html += f'<h3>메모리 사용률</h3><img src="data:image/png;base64,{graphs["memory_graph"]}" alt="Memory Graph" style="width:100%;">'
            if 'network_graph' in graphs: graph_html += f'<h3>네트워크 트래픽</h3><img src="data:image/png;base64,{graphs["network_graph"]}" alt="Network Graph" style="width:100%;">'
            graph_html += '</div>'
        
        # NETDEV 테이블 생성
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

        # ETHTOOL 테이블 생성
        ethtool_rows = ""
        ethtool_data = network_details.get('ethtool', {})
        for iface, data in ethtool_data.items():
            ethtool_rows += f"<tr><td>{html.escape(iface)}</td><td>{html.escape(data.get('link', 'N/A'))}</td><td>{html.escape(data.get('speed', 'N/A'))}</td><td>{html.escape(data.get('driver', 'N/A'))}</td><td>{html.escape(data.get('firmware', 'N/A'))}</td></tr>"

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
        .container {{ max-width: 900px; margin: auto; background: #fff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); overflow: hidden; }}
        header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
        header h1 {{ margin: 0; font-size: 24px; }}
        .content {{ padding: 20px; }}
        .section {{ margin-bottom: 20px; }}
        .section h2 {{ border-bottom: 2px solid #007bff; padding-bottom: 10px; margin-bottom: 15px; color: #007bff; }}
        .info-table, .data-table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .info-table th, .info-table td, .data-table th, .data-table td {{ border: 1px solid #ddd; padding: 10px; text-align: left; word-break: break-all; }}
        .info-table th {{ background-color: #f2f2f2; width: 25%; font-weight: bold; }}
        .data-table th {{ background-color: #f2f2f2; font-weight: bold; }}
        .issue-list li {{ background: #fff3cd; border-left: 4px solid #ffc107; margin-bottom: 10px; padding: 10px; list-style-type: none; }}
        .critical-list li {{ background: #f8d7da; border-left-color: #dc3545; }}
        .ai-summary-card {{ background-color: #e9ecef; padding: 20px; border-radius: 8px; }}
        .ai-status {{ font-size: 1.5em; font-weight: bold; color: {status_color}; }}
        footer {{ text-align: center; padding: 15px; font-size: 12px; color: #888; background-color: #f4f7f9; }}
    </style>
</head>
<body>
    <div class="container">
        <header><h1>S-Core System Report</h1></header>
        <div class="content">
            <div class="section">
                <h2>ℹ️ 시스템 요약</h2>
                <table class="info-table">
                    <tr><th>Hostname</th><td>{html.escape(system_info.get('hostname', 'N/A'))}</td></tr>
                    <tr><th>OS Version</th><td>{html.escape(system_info.get('os_version', 'N/A'))}</td></tr>
                    <tr><th>Kernel</th><td>{html.escape(system_info.get('kernel', 'N/A'))}</td></tr>
                    <tr><th>System Model</th><td>{html.escape(system_info.get('system_model', 'N/A'))}</td></tr>
                    <tr><th>CPU</th><td>{html.escape(system_info.get('cpu', 'N/A'))}</td></tr>
                    <tr><th>Memory</th><td>{html.escape(system_info.get('memory', 'N/A'))}</td></tr>
                    <tr><th>Uptime</th><td>{html.escape(system_info.get('uptime', 'N/A'))}</td></tr>
                    <tr><th>Last Boot</th><td>{html.escape(system_info.get('last_boot', 'N/A'))}</td></tr>
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
                <pre style="background:#eee; padding:10px; border-radius:4px;">{html.escape(chr(10).join(network_details.get('sockstat', [])))}</pre>
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
                <table class="info-table">
                    <tr><th>Total Processes</th><td>{process_stats.get('total', 'N/A')}</td></tr>
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
                    <thead><tr><th>PID</th><th>User</th><th>CPU %</th><th>Command</th></tr></thead>
                    <tbody>{create_table_rows(process_stats.get('top_cpu', []), ['pid', 'user', 'cpu%', 'command'])}</tbody>
                </table>
                <h3>Top 5 Processes (Memory)</h3>
                <table class="data-table">
                    <thead><tr><th>PID</th><th>User</th><th>RSS (KiB)</th><th>Command</th></tr></thead>
                    <tbody>{create_table_rows(process_stats.get('top_mem', []), ['pid', 'user', 'rss', 'command'])}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>🔧 실패한 서비스</h2>
                <ul class="issue-list critical-list">{''.join(f"<li>{html.escape(service)}</li>" for service in failed_services) or "<li>실패한 서비스가 없습니다.</li>"}</ul>
            </div>

            <!-- AI 분석 섹션 -->
            <div class="section">
                <h2>🚨 AI 분석: 심각한 이슈 ({len(critical_issues)}개)</h2>
                <ul class="issue-list critical-list">{''.join(f"<li>{html.escape(issue)}</li>" for issue in critical_issues) or "<li>발견된 심각한 이슈가 없습니다.</li>"}</ul>
            </div>
            <div class="section">
                <h2>⚠️ AI 분석: 경고 사항 ({len(warnings)}개)</h2>
                <ul class="issue-list">{''.join(f"<li>{html.escape(warning)}</li>" for warning in warnings) or "<li>특별한 경고 사항이 없습니다.</li>"}</ul>
            </div>
            <div class="section">
                <h2>💡 AI 분석: 권장사항 ({len(recommendations)}개)</h2>
                <table class="data-table">
                    <thead><tr><th>우선순위</th><th>카테고리</th><th>문제점</th><th>해결 방안</th></tr></thead>
                    <tbody>{create_table_rows(recommendations, ['priority', 'category', 'issue', 'solution'])}</tbody>
                </table>
            </div>
            <div class="section">
                <h2>🤖 AI 종합 분석</h2>
                <div class="ai-summary-card">
                    <p><b>종합 상태:</b> <span class="ai-status">{status}</span> (건강도 점수: {score}/100)</p>
                    <p><b>요약:</b> {summary}</p>
                </div>
            </div>

            <!-- 보안 뉴스 섹션 (AI 분석 섹션 뒤로 이동) -->
            <div class="section">
                <h2>🛡️ 보안 뉴스 (가장 중요한 5개)</h2>
                <table class="data-table">
                    <thead><tr><th>CVE 식별자</th><th>심각도</th><th>생성일</th><th>요약</th><th>국내외 동향</th></tr></thead>
                    <tbody>{create_table_rows(security_news, ['CVE', 'severity', 'public_date', 'bugzilla_description', 'trends'], "보안 뉴스 정보를 가져오지 못했습니다.")}</tbody>
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
    """Windows 경로에서 유효하지 않은 문자를 '_'로 바꾸는 필터 함수"""
    member.name = member.name.replace(':', '_')
    return member

def decompress_sosreport(archive_path: str, extract_dir: str) -> str:
    """sosreport 압축 파일을 지정된 디렉토리에 해제합니다."""
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
    """
    shutil.rmtree를 위한 오류 핸들러.
    PermissionError가 발생하면 파일 권한을 변경하고 작업을 재시도합니다.
    """
    if isinstance(exc_info[1], PermissionError):
        try:
            os.chmod(path, 0o777)
            func(path)
        except Exception as e:
            print(f"onerror 핸들러에서도 파일 처리 실패: {path}, 오류: {e}")

def main():
    """메인 함수"""
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
            print(f"✅ 추출된 데이터 JSON 파일로 저장 완료: {parsed_data_path}")
        except Exception as e:
            print(f"❌ 추출된 데이터 JSON 저장 실패: {e}")

        prompt = analyzer.create_analysis_prompt(sos_data)
        result = analyzer.perform_ai_analysis(prompt)
        print("✅ AI 시스템 분석 완료!")

        # 보안 뉴스 데이터 가져오기
        sos_data['security_news'] = analyzer.fetch_security_news()
        
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
            print(f"  - 원본 추출 데이터 (JSON): {results['extracted_data_file']}")

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
