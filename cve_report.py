# 필요한 라이브러리를 설치해주세요: pip install requests openpyxl beautifulsoup4 lxml
import requests
import argparse
from datetime import datetime, timedelta
from openpyxl import Workbook
from bs4 import BeautifulSoup
import os
import time

def get_cve_data(start_date, end_date):
    """
    Red Hat으로부터 지정된 기간 동안의 CVE 데이터를 가져옵니다.
    """
    start_date_str = start_date.strftime('%Y-%m-%d')
    end_date_str = end_date.strftime('%Y-%m-%d')
    url = f"https://access.redhat.com/hydra/rest/securitydata/cve.json?after={start_date_str}&before={end_date_str}"
    
    print(f"데이터 수집 중... (기간: {start_date_str} ~ {end_date_str})")
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP 오류 발생: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f"요청 중 오류 발생: {req_err}")
    except ValueError as json_err:
        print(f"JSON 파싱 오류: {json_err}")
    return None

def get_llm_summary(text, cve_id, cvss_score, llm_url, api_token, model):
    """
    내부 LLM을 사용하여 CVE에 대한 핵심 요약을 요청합니다.
    """
    if not text or text == '요약 정보 없음':
        return '요약 정보 없음'
    
    endpoint_path = "/v1/chat/completions"
    if not llm_url.endswith(endpoint_path):
        completion_url = llm_url.rstrip('/') + endpoint_path
    else:
        completion_url = llm_url

    headers = {
        'Authorization': f'Bearer {api_token}',
        'Content-Type': 'application/json'
    }
    
    prompt = f"""당신은 최고의 Red Hat 보안 분석가입니다. 다음 CVE 기술 설명을 "Web Search"를 활성화하여 분석하고, 이 취약점의 **핵심 위협과 시스템에 미치는 가장 치명적인 영향을 한 문장으로 압축**하여 한국어로 요약해 주세요.

[CVE 정보]
- CVE ID: {cve_id}
- CVSSv3 Score: {cvss_score}
- 기술 설명:
---
{text}
---

[출력 형식]
(예시: "특정 라이브러리의 취약점을 통해 원격 공격자가 루트 권한을 획득할 수 있습니다.")
다른 설명 없이, 오직 핵심 요약 한 문장만 출력해야 합니다.
"""
    
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a top-tier security analyst specializing in Red Hat Enterprise Linux."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 200,
        "temperature": 0.1,
        "stream": False
    }
    
    try:
        print(f"    - LLM 요약 요청 중... (URL: {completion_url})")
        response = requests.post(completion_url, headers=headers, json=payload, timeout=60)
        response.raise_for_status()
        data = response.json()
        
        if 'choices' in data and data['choices']:
            summary = data['choices'][0].get('message', {}).get('content', '')
            if summary:
                return summary.strip()

        print(f"    - LLM 응답에서 요약 내용을 찾을 수 없습니다. 원본 응답: {data}")
        return "LLM 응답 파싱 실패"

    except requests.exceptions.RequestException as e:
        print(f"    - LLM API 호출 오류: {e}")
        return "LLM 요약 실패"
    except (KeyError, IndexError, TypeError) as e:
        print(f"    - LLM 응답 파싱 오류: {e}")
        return "LLM 응답 파싱 실패"

def generate_excel_report(cves, filename='redhat_cve_report.xlsx'):
    """
    CVE 데이터를 사용하여 Excel 보고서(.xlsx)를 생성합니다.
    """
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "CVE Report"

    headers = ['CVE ID', '심각도', 'CVSSv3 점수', '발생 일자', '영향받는 제품', '영향받는 패키지', '요약', '링크']
    sheet.append(headers)

    for cve in cves:
        cve_id = cve.get('CVE', 'N/A')
        severity = cve.get('severity', 'N/A')
        if isinstance(severity, list):
            severity = ', '.join(map(str, severity))
        
        cvss3_score = cve.get('cvss3_score', 'N/A')
        
        public_date = cve.get('public_date', 'N/A')
        if public_date and 'T' in public_date:
            public_date = public_date.split('T')[0]
            
        affected_products = ', '.join(cve.get('affected_products', []))
        
        affected_packages_list = cve.get('affected_packages', [])
        package_strings = []
        for pkg in affected_packages_list:
            pkg_name = pkg.get('name', 'N/A')
            status = pkg.get('status')
            icon = ''
            if status == 'fixed':
                icon = '✅ '
            elif status == 'not_fixed':
                icon = '🔧 '
            package_strings.append(f"{icon}{pkg_name}")
        affected_packages = ', '.join(package_strings)

        summary = cve.get('llm_summary', '요약 정보 없음')
        cve_link = f"https://access.redhat.com/security/cve/{cve_id}"

        sheet.append([cve_id, str(severity), cvss3_score, public_date, affected_products, affected_packages, summary, cve_link])
    
    try:
        workbook.save(filename)
        print(f"Excel 보고서가 '{os.path.abspath(filename)}' 파일로 저장되었습니다.")
    except IOError as e:
        print(f"Excel 파일 저장 중 오류 발생: {e}")


def generate_html_report(cves, start_date, end_date, html_filename='redhat_cve_report.html', excel_filename='redhat_cve_report.xlsx'):
    """
    CVE 데이터를 사용하여 HTML 보고서를 생성합니다.
    """
    # SVG 아이콘 정의
    wrench_svg_icon = """
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#d9534f" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: middle; margin-right: 4px;">
        <path d="M3 21h4l13 -13a1.5 1.5 0 0 0 -2 -2l-13 13v4" />
        <line x1="14.5" y1="5.5" x2="18.5" y2="9.5" />
        <path d="M12 8l-5 -5l-4 4l5 5" />
        <line x1="7" y1="8" x2="8.5" y2="9.5" />
        <path d="M16 12l5 5l-4 4l-5 -5" />
        <line x1="16" y1="17" x2="17.5" y2="18.5" />
    </svg>
    """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Red Hat 보안 보고서</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f4f7f6; color: #333; }}
            .container {{ max-width: 1200px; margin: auto; background-color: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
            h1 {{ color: #c00; border-bottom: 2px solid #c00; padding-bottom: 10px; margin-bottom: 20px; }}
            p {{ font-size: 1.1em; color: #555; }}
            .header-flex {{ display: flex; justify-content: space-between; align-items: center; }}
            .excel-button {{ background-color: #217346; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; }}
            .excel-button:hover {{ background-color: #185232; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 13px; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; vertical-align: top; word-wrap: break-word; }}
            th {{ background-color: #333; color: #fff; font-weight: bold; white-space: nowrap; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            tr:hover {{ background-color: #f1f1f1; }}
            a {{ color: #007bff; text-decoration: none; }}
            a:hover {{ text-decoration: underline; }}
            ul {{ margin: 0; padding-left: 20px; list-style-type: none; }}
            .footer {{ text-align: center; margin-top: 30px; font-size: 0.9em; color: #888; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header-flex">
                <h1>Red Hat 보안 보고서</h1>
                <a href="{excel_filename}" download class="excel-button">Excel로 다운로드</a>
            </div>
            <p><strong>조회 기간:</strong> {start_date.strftime('%Y-%m-%d')} ~ {end_date.strftime('%Y-%m-%d')}</p>
            <p><strong>총 발견된 CVE (RHEL 7-10 대상):</strong> {len(cves)}개</p>
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>심각도</th>
                        <th>CVSSv3 점수</th>
                        <th>발생 일자</th>
                        <th>영향받는 제품</th>
                        <th>영향받는 패키지</th>
                        <th>요약</th>
                    </tr>
                </thead>
                <tbody>
    """

    for cve in cves:
        cve_id = cve.get('CVE', 'N/A')
        severity = cve.get('severity', 'N/A')
        if isinstance(severity, list):
            severity = ', '.join(map(str, severity))
        
        cvss3_score = cve.get('cvss3_score', 'N/A')

        public_date = cve.get('public_date', 'N/A')
        if public_date and 'T' in public_date:
            public_date = public_date.split('T')[0]
            
        affected_products_list = cve.get('affected_products', [])
        affected_products_html = "<ul>" + "".join([f"<li>{p}</li>" for p in affected_products_list]) + "</ul>"

        affected_packages_list = cve.get('affected_packages', [])
        affected_packages_html = "<ul>"
        if not affected_packages_list:
            affected_packages_html += "<li>정보 없음</li>"
        else:
            for pkg in affected_packages_list:
                pkg_name = pkg.get('name', 'N/A')
                status = pkg.get('status')
                icon = ''
                if status == 'fixed':
                    icon = '✅ ' # Fix icon
                elif status == 'not_fixed':
                    icon = wrench_svg_icon # Not fix icon (monkey wrench)
                affected_packages_html += f"<li>{icon}{pkg_name}</li>"
        affected_packages_html += "</ul>"


        summary = cve.get('llm_summary', '요약 정보 없음').replace('\n', '<br>')
        cve_link = f"https://access.redhat.com/security/cve/{cve_id}"

        html_content += f"""
                    <tr>
                        <td><a href="{cve_link}" target="_blank">{cve_id}</a></td>
                        <td>{str(severity)}</td>
                        <td>{cvss3_score}</td>
                        <td>{public_date}</td>
                        <td>{affected_products_html}</td>
                        <td>{affected_packages_html}</td>
                        <td>{summary}</td>
                    </tr>
        """

    html_content += """
                </tbody>
            </table>
            <div class="footer">
                <p>이 보고서는 Red Hat Security Data API 및 내부 AI를 기반으로 생성되었습니다.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    try:
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"HTML 보고서가 '{os.path.abspath(html_filename)}' 파일로 저장되었습니다.")
    except IOError as e:
        print(f"HTML 파일 저장 중 오류 발생: {e}")

def parse_cve_data(cve_data, start_date, end_date, args):
    """
    가져온 CVE 데이터에서 심각도 및 제품 기준으로 필터링하고 처리합니다.
    """
    if not cve_data:
        print("처리할 CVE 데이터가 없습니다.")
        return

    target_severities = ['important', 'critical']
    target_cves = []
    for cve in cve_data:
        severity = cve.get('severity')
        is_target_severity = False
        if isinstance(severity, str):
            if any(sev in severity.lower() for sev in target_severities):
                is_target_severity = True
        elif isinstance(severity, list):
            if any(any(sev in str(s).lower() for sev in target_severities) for s in severity):
                is_target_severity = True
        if is_target_severity:
            target_cves.append(cve)

    if not target_cves:
        print(f"'{', '.join(target_severities)}' 심각도를 가진 CVE를 찾을 수 없습니다.")
        return
    
    if args.limit and len(target_cves) > args.limit:
        print(f"\n--limit 옵션에 따라 최신 {args.limit}개의 CVE만 처리합니다. (총 {len(target_cves)}개 발견)")
        target_cves = target_cves[:args.limit]
    
    print(f"\n{len(target_cves)}개의 '{', '.join(target_severities)}' 등급 CVE를 찾았습니다. 이제 RHEL 제품 해당 여부 및 상세 정보를 확인합니다...")

    target_products = {"Red Hat Enterprise Linux 10", "Red Hat Enterprise Linux 9", "Red Hat Enterprise Linux 8", "Red Hat Enterprise Linux 7"}
    final_cves = []
    for cve in target_cves:
        cve_id = cve.get('CVE')
        if not cve_id: continue

        print(f"  - {cve_id} 상세 정보 확인 중...")
        detail_url_json = f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"
        detail_url_html = f"https://access.redhat.com/security/cve/{cve_id}"
        
        try:
            res_json = requests.get(detail_url_json, timeout=30)
            res_json.raise_for_status()
            detail_data = res_json.json()
            
            affected_products_found = set()
            affected_packages_list = []
            processed_packages = set()

            # 1. 'affected_release'에서 'fixed' 패키지 정보 수집
            affected_releases = detail_data.get('affected_release', [])
            for release in affected_releases:
                product_name = release.get('product_name', '')
                advisory = release.get('advisory')
                package_nvr = release.get('package')
                
                if product_name in target_products and advisory and package_nvr and package_nvr not in processed_packages:
                    abbreviated_name = product_name.replace("Red Hat Enterprise Linux", "RHEL")
                    affected_products_found.add(abbreviated_name)
                    affected_packages_list.append({'name': package_nvr, 'status': 'fixed'})
                    processed_packages.add(package_nvr)

            # 2. 'package_state'에서 'not fixed' 패키지 정보 수집
            package_states = detail_data.get('package_state', [])
            for state in package_states:
                product_name = state.get('product_name', '')
                fix_state = state.get('fix_state', '')
                package_name = state.get('package_name')

                if product_name in target_products and package_name and fix_state == 'Affected' and package_name not in processed_packages:
                    abbreviated_name = product_name.replace("Red Hat Enterprise Linux", "RHEL")
                    affected_products_found.add(abbreviated_name)
                    affected_packages_list.append({'name': package_name, 'status': 'not_fixed'})
                    processed_packages.add(package_name)

            if affected_products_found:
                # --- 요약 정보 소스 결정 (API 우선) ---
                summary_source = ''
                statement = detail_data.get('statement')
                details_list = detail_data.get('details', [])
                details_text = ' '.join(details_list) if details_list else ''
                
                # API의 statement나 details 필드를 우선 사용
                summary_source = statement or details_text
                
                # API 데이터가 없을 경우에만 HTML 스크래핑 시도
                if not summary_source:
                    print("    - API 요약 정보 없음. HTML 페이지 스크래핑 시도...")
                    for attempt in range(3):
                        try:
                            res_html = requests.get(detail_url_html, timeout=30)
                            res_html.raise_for_status()
                            soup = BeautifulSoup(res_html.text, 'lxml')
                            description_div = soup.find('div', id='description')
                            if description_div:
                                summary_source = ' '.join(description_div.get_text(strip=True).split())
                            break 
                        except requests.exceptions.RequestException as e:
                            print(f"    - {cve_id} HTML 페이지 조회 실패 (시도 {attempt + 1}/3): {e}")
                            if attempt < 2:
                                time.sleep(2)
                
                # 모든 방법 실패 시 bugzilla 설명으로 대체
                if not summary_source:
                    summary_source = cve.get('bugzilla_description', '요약 정보 없음')

                cvss3_score = detail_data.get('cvss3', {}).get('cvss3_base_score', 'N/A')

                llm_summary = get_llm_summary(summary_source, cve_id, cvss3_score, args.llm_url, args.api_token, args.model)
                
                cve['llm_summary'] = llm_summary
                cve['cvss3_score'] = cvss3_score
                cve['affected_products'] = sorted(list(affected_products_found))
                cve['affected_packages'] = sorted(affected_packages_list, key=lambda x: x['name'])
                
                print(f"    -> RHEL 대상 CVE 확인: {cve_id} (CVSSv3: {cvss3_score})")
                final_cves.append(cve)

            time.sleep(0.1)

        except requests.exceptions.RequestException as e:
            print(f"    - {cve_id} JSON API 조회 실패: {e}")

    if not final_cves:
        print(f"\nRHEL 7, 8, 9, 10에 해당하고 'Affected' 상태이거나 'advisory'가 존재하는 CVE를 찾을 수 없습니다.")
        return

    print(f"\n총 {len(final_cves)}개의 RHEL 대상 CVE가 발견되었습니다. 보고서 파일을 생성합니다...")
    
    generate_excel_report(final_cves)
    generate_html_report(final_cves, start_date, end_date)


def main():
    """
    스크립트의 메인 실행 함수.
    """
    parser = argparse.ArgumentParser(description="Red Hat CVE 보안 보고서 생성기")
    
    parser.add_argument('--months', type=int, help="현재로부터 N개월 전까지의 데이터를 수집합니다.")
    parser.add_argument('--days', type=int, help="현재로부터 N일 전까지의 데이터를 수집합니다.")
    parser.add_argument('--startdate', type=str, help="시작 날짜 (YYYY-MM-DD 형식)")
    parser.add_argument('--enddate', type=str, help="종료 날짜 (YYYY-MM-DD 형식)")
    parser.add_argument('--limit', type=int, help="처리할 최신 CVE의 최대 수량을 지정합니다.")

    parser.add_argument('--llm-url', type=str, required=True, help="LLM API 엔드포인트 URL")
    parser.add_argument('--api-token', type=str, required=True, help="LLM API 인증 토큰")
    parser.add_argument('--model', type=str, required=True, help="사용할 LLM 모델 이름")

    args = parser.parse_args()

    end_date = datetime.now()
    start_date = None

    if args.startdate and args.enddate:
        try:
            start_date = datetime.strptime(args.startdate, '%Y-%m-%d')
            end_date = datetime.strptime(args.enddate, '%Y-%m-%d')
        except ValueError:
            print("오류: 날짜 형식이 잘못되었습니다. 'YYYY-MM-DD' 형식으로 입력해주세요.")
            return
    elif args.months:
        start_date = end_date - timedelta(days=args.months * 30)
    elif args.days:
        start_date = end_date - timedelta(days=args.days)
    else:
        start_date = end_date - timedelta(days=30)

    if start_date:
        cve_data = get_cve_data(start_date, end_date)
        parse_cve_data(cve_data, start_date, end_date, args)

if __name__ == "__main__":
    main()
