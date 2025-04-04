import argparse
import requests
import random
import time
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode
from bs4 import BeautifulSoup
from tqdm import tqdm
from threading import Lock
import re
from datetime import datetime
import os
import html

# 启动横幅
BANNER = r"""
\033[31m
 ██╗  ██╗███████╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ╚██╗██╔╝██╔════╝██╔════╝██╔════╝██╔══██╗████╗  ██║
  ╚███╔╝ ███████╗███████╗██║     ███████║██╔██╗ ██║
  ██╔██╗ ╚════██║╚════██║██║     ██╔══██║██║╚██╗██║
 ██╔╝ ██╗███████║███████║╚██████╗██║  ██║██║ ╚████║
 ╚═╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
  ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
  █░▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀░█
  █░       X S S   C A N N E R   V1.2            ░█
  █░                作者@意朽                    ░█
  ▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
\033[0m
"""

# 配置参数
MAX_THREADS = 20
REQUEST_TIMEOUT = 10
BASE_DELAY = 0.5
MAX_DEPTH = 3
MAX_RETRIES = 2

# 全局变量
visited_urls = set()
request_fingerprints = set()
url_lock = Lock()
session = requests.Session()
# 配置session保持cookie和重定向
session.max_redirects = 5
session.trust_env = False
session.cookies.clear()  # 清除默认cookie
xss_payload = "<phjE3t>"
xss_payload1 = "%3CphjE3t%3E"

def escape_html_content(text):
    """转义HTML特殊字符，同时保留标签可见性"""
    return html.escape(text).replace('<', '<span class="html-tag"><').replace('>', '></span>')

def get_request_fingerprint(method, url, data):
    """生成请求唯一指纹"""
    sorted_data = urlencode(sorted(data.items())) if data else ""
    return f"{method}_{url}_{sorted_data}"

def normalize_url(url):
    """标准化URL用于去重"""
    try:
        parsed = urlparse(url)
        path = parsed.path.rstrip('/') or '/'
        if '#' in path:
            path = path.split('#')[0]
        
        query = parse_qs(parsed.query, keep_blank_values=True)
        sorted_query = sorted(query.items())
        normalized_query = urlencode(sorted_query, doseq=True)
        
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            path,
            parsed.params,
            normalized_query,
            ''
        ))
        return normalized
    except Exception as e:
        return url

def get_random_headers(cookie=None):
    """生成随机请求头"""
    headers = {
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate"
    }
    if cookie:
        headers["Cookie"] = cookie
    return headers

def fetch_page(url, cookie=None):
    """获取页面内容(增强反爬能力)"""
    for attempt in range(MAX_RETRIES):
        try:
            # 随机延迟 + 模拟人类浏览行为
            time.sleep(BASE_DELAY * random.uniform(0.8, 1.2))
            
            # 对于后台页面，必须跟随重定向
            allow_redirects = True if cookie else random.choice([True, False])
            
            # 确保cookie正确传递
            headers = get_random_headers(cookie)
            if cookie:
                # 同时设置session cookie和请求头cookie
                session.cookies.clear()
                for c in cookie.split(';'):
                    name, value = c.strip().split('=', 1)
                    session.cookies.set(name, value)
                headers["Cookie"] = cookie
                
            # 随机添加Referer头
            if random.random() > 0.3:  # 70%概率添加Referer
                parsed = urlparse(url)
                headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}"
            
            # 随机添加其他常见头
            if random.random() > 0.5:
                headers["DNT"] = random.choice(["1", "0"])
            
            # 随机化请求参数顺序
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query, keep_blank_values=True)
                if random.random() > 0.5:  # 50%概率打乱参数顺序
                    keys = list(params.keys())
                    random.shuffle(keys)
                    shuffled_params = {k: params[k] for k in keys}
                    url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        urlencode(shuffled_params, doseq=True),
                        parsed.fragment
                    ))
            
            response = session.get(
                url,
                headers=headers,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=allow_redirects
            )
            
            # 随机延迟处理响应
            if random.random() > 0.7:
                time.sleep(random.uniform(0.1, 0.5))
                
            response.raise_for_status()
            return response.text
        except requests.exceptions.Timeout:
            if attempt == MAX_RETRIES - 1:
                continue
        except Exception as e:
            if attempt == MAX_RETRIES - 1:
                continue
    return None

def extract_links(html_content, base_url):
    """提取所有有效链接"""
    if not html_content:
        return set()
    
    soup = BeautifulSoup(html_content, 'html.parser')
    links = set()
    static_ext = re.compile(r'\.(css|js|jpg|jpeg|png|gif|pdf|zip|rar|tar|gz|svg|ico|woff|woff2|ttf|eot)(\?|$)', re.I)
    
    for tag in soup.find_all(['a', 'link', 'script', 'img', 'iframe'], href=True):
        link = urljoin(base_url, tag['href'])
        if not static_ext.search(link):
            links.add(link)
    
    for tag in soup.find_all(['img', 'script', 'iframe'], src=True):
        link = urljoin(base_url, tag['src'])
        if not static_ext.search(link):
            links.add(link)
    
    return links

def extract_forms(html_content, base_url):
    """提取表单数据"""
    if not html_content:
        return []
    
    soup = BeautifulSoup(html_content, 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        form_data = {
            'action': urljoin(base_url, form.get('action', '')),
            'method': form.get('method', 'GET').upper(),
            'inputs': []
        }
        
        for inp in form.find_all(['input', 'textarea', 'select']):
            if inp.get('type') in ['submit', 'button', 'image']:
                continue
                
            input_data = {
                'name': inp.get('name'),
                'value': inp.get('value', ''),
                'type': inp.get('type', 'text')
            }
            
            if input_data['name']:
                form_data['inputs'].append(input_data)
        
        forms.append(form_data)
    
    return forms

def test_xss_get(url, cookie=None):
    """测试GET请求中的XSS漏洞"""
    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    
    if not query:
        return None
    
    # 构造恶意URL
    malicious_query = {}
    for param in query:
        malicious_query[param] = xss_payload
    
    malicious_url = urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        urlencode(malicious_query, doseq=True),
        parsed.fragment
    ))
    
    try:
        headers = get_random_headers(cookie)
        if cookie:
            headers["Cookie"] = cookie
        response = session.get(
            malicious_url,
            headers=headers,
            timeout=REQUEST_TIMEOUT
        )
        
        return {
            'request': {
                'url': malicious_url,
                'method': 'GET',
                'headers': get_random_headers(),
                'data': '',  # GET请求参数在 URL 中
                'fingerprint': get_request_fingerprint('GET', url, malicious_query)
            },
            'response': {
                'status': response.status_code,
                'text': response.text,
                'length': len(response.content),
                'headers': dict(response.headers)
            },
            'vulnerable': xss_payload in response.text,
            'fingerprint': get_request_fingerprint('GET', url, malicious_query)
        }
    except Exception as e:
        return {'error': str(e)}

def submit_form(form, cookie=None):
    """提交表单（严格去重）"""
    global request_fingerprints
    
    try:
        data = {inp['name']: inp['value'] for inp in form['inputs']}
        fingerprint = get_request_fingerprint(form['method'], form['action'], data)
        
        with url_lock:
            if fingerprint in request_fingerprints:
                return {
                    'request': None,
                    'response': None,
                    'vulnerable': False,
                    'fingerprint': fingerprint
                }
            request_fingerprints.add(fingerprint)
        
        headers = get_random_headers(cookie)
        if cookie:
            headers["Cookie"] = cookie
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        if form['method'] == 'POST':
            response = session.post(
                form['action'],
                data=data,
                headers=headers,
                timeout=REQUEST_TIMEOUT
            )
        else:
            # GET方式提交表单
            return test_xss_get(form['action'] + '?' + urlencode(data))
        
        return {
            'request': {
                'url': form['action'],
                'method': form['method'],
                'headers': headers,
                'data': urlencode(data),
                'fingerprint': fingerprint
            },
            'response': {
                'status': response.status_code,
                'text': response.text,
                'length': len(response.content),
                'headers': dict(response.headers)
            },
            'vulnerable': xss_payload in response.text,
            'fingerprint': fingerprint
        }
    except Exception as e:
        return {'error': str(e)}

def process_page(url, current_depth, max_depth, results, cookie=None):
    """处理单个页面"""
    normalized_url = normalize_url(url)
    
    with url_lock:
        if normalized_url in visited_urls or current_depth > max_depth:
            return []
        visited_urls.add(normalized_url)
    
    try:
        # 确保cookie正确传递到fetch_page
        html_content = fetch_page(url, cookie)
        if not html_content:
            return []
        
        # 检查是否是登录后的页面
        if cookie and "logout" in html_content.lower():
            print(f"[+] 成功访问受保护页面: {url}")
        
        links = extract_links(html_content, url)
        forms = extract_forms(html_content, url)
        
        with url_lock:
            results['links'].update(links)
            results['forms'].extend(forms)
        
        # 确保cookie传递给所有子页面
        return [(link, cookie) for link in links if normalize_url(link) not in visited_urls]
    except Exception as e:
        return []

def crawl(start_url, max_depth, cookie=None):
    """主爬取函数"""
    manager = {
        'links': set(),
        'forms': [],
        'lock': Lock()
    }
    
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {
            executor.submit(process_page, start_url, 0, max_depth, manager, cookie): start_url
        }
        
        with tqdm(desc="爬取进度", unit="page") as pbar:
            while futures:
                done = set()
                try:
                    done, _ = as_completed(futures, timeout=REQUEST_TIMEOUT * 2), set()
                except TimeoutError:
                    done = [f for f in futures if f.done()]
                
                for future in done:
                    url = futures.pop(future)
                    try:
                        new_links = future.result()
                    except Exception as e:
                        continue
                    
                    for link_info in new_links:
                        if isinstance(link_info, tuple):
                            link, link_cookie = link_info
                        else:
                            link = link_info
                            link_cookie = cookie
                            
                        norm_link = normalize_url(link)
                        if norm_link not in visited_urls:
                            parsed = urlparse(link)
                            depth = len([p for p in parsed.path.split('/') if p])
                            if depth <= max_depth:
                                futures[executor.submit(
                                    process_page, 
                                    link, 
                                    depth, 
                                    max_depth, 
                                    manager,
                                    link_cookie
                                )] = link
                    
                    pbar.update(1)
                    pbar.set_postfix({
                        '链接': len(manager['links']),
                        '表单': len(manager['forms']),
                    })
    
    return manager

def extract_payload_context(response_text, payload, context_length=30):
    """
    从响应文本中提取payload上下文：
    返回payload出现处前后各context_length字符组成的片段，如果没找到则返回空字符串
    """
    idx = response_text.find(payload)
    if idx == -1:
        return ""
    start = max(idx - context_length, 0)
    end = idx + len(payload) + context_length
    snippet = response_text[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(response_text):
        snippet = snippet + "..."
    return snippet

def generate_html_report(vulnerabilities, output_path):
    """生成可折叠的HTML报告，确保所有内容正确显示"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    def format_content(text):
        """格式化响应内容，只显示payload上下文"""
        context = extract_payload_context(text, xss_payload)
        escaped = html.escape(context)
        escaped = escaped.replace('<', '<span class="html-tag"><').replace('>', '></span>')
        escaped = escaped.replace(html.escape(xss_payload), f'<span style="color:red;font-weight:bold">{html.escape(xss_payload)}</span>')
        return escaped

    # 统计POST和GET漏洞数量
    post_count = sum(1 for vuln in vulnerabilities if vuln['result']['request']['method'].upper() == 'POST')
    get_count = sum(1 for vuln in vulnerabilities if vuln['result']['request']['method'].upper() == 'GET')
    
    # 构建漏洞列表HTML
    vuln_items = []
    for i, vuln in enumerate(vulnerabilities, 1):
        req = vuln['result']['request']
        req_headers = "".join(f"{k}: {v}" + "\n" for k, v in req['headers'].items())
        res_headers = "".join(f"{k}: {v}" + "\n" for k, v in vuln['result']['response']['headers'].items())
        
        # 添加完整的请求头信息
        full_request = f"{vuln['result']['request']['method']} {vuln['result']['request']['url']} HTTP/1.1\n"
        full_request += req_headers
        if vuln['result']['request']['data']:
            full_request += "\n" + vuln['result']['request']['data']
        
        req_method = vuln['result']['request']['method']
        req_data = vuln['result']['request']['data']
        if not req_data and req_method.upper() == "GET":
            parsed = urlparse(vuln['result']['request']['url'])
            req_data = parsed.query if parsed.query else '无'
        elif not req_data:
            req_data = '无'
            
        vuln_items.append(f'''
        <article class="vulnerability">
            <details>
                <summary style="color: {'#ff6b6b' if req_method == 'POST' else '#4ecdc4'}">【{html.escape(req_method)}】 漏洞 #{i} - {html.escape(vuln['result']['request']['url'])}</summary>
                <div class="detail-grid">
                    <div class="detail-label">请求方法：</div>
                    <div class="detail-value" style="color: {'#ff6b6b' if req_method == 'POST' else '#4ecdc4'}">{html.escape(req_method)}</div>
                    
                    <div class="detail-label">目标URL：</div>
                    <div class="detail-value"><code>{html.escape(vuln['result']['request']['url'])}</code></div>
                    
                    <div class="detail-label">请求参数：</div>
                    <div class="detail-value">
                        <div class="scrollable-content" style="max-height: 200px; overflow: auto; border: 1px solid #ddd; padding: 5px;">
                            <pre style="white-space: pre-wrap; margin: 0;">{html.escape(req_data)}</pre>
                        </div>
                    </div>
                    
                    <div class="detail-label">完整请求：</div>
                    <div class="detail-value">
                        <div class="scrollable-content" style="max-height: 200px; overflow: auto; border: 1px solid #ddd; padding: 5px;">
                            <pre class="headers" style="white-space: pre-wrap; margin: 0;">{full_request}</pre>
                        </div>
                    </div>
                    
                    <div class="detail-label">响应状态：</div>
                    <div class="detail-value">{vuln['result']['response']['status']}</div>
                    
                    <div class="detail-label">响应头：</div>
                    <div class="detail-value">
                        <pre class="headers">{res_headers}</pre>
                    </div>
                    
                    <div class="detail-label">响应长度：</div>
                    <div class="detail-value">{vuln['result']['response']['length']} 字节</div>
                    
                    <div class="detail-label">Payload位置：</div>
                    <div class="detail-value">{vuln['result']['response']['text'].find(xss_payload)}</div>
                    
                    <div class="detail-label">Payload上下文：</div>
                    <div class="detail-value">
                        <div class="scrollable-content" style="max-height: 200px; overflow: auto; border: 1px solid #ddd; padding: 5px;">
                            <pre style="white-space: pre-wrap; margin: 0;">{format_content(vuln['result']['response']['text'])}</pre>
                        </div>
                    </div>
                </div>
            </details>
        </article>
        ''')
    
    vuln_list = "\n".join(vuln_items) if vulnerabilities else "<p>未发现漏洞</p>"

    html_template = f'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>XSS漏洞扫描报告</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;700&display=swap');
        
        :root {{
            --primary-color: #e0e0e0;
            --secondary-color: #bb86fc;
            --background-color: #121212;
            --surface-color: #1e1e1e;
            --border-color: #333333;
            --highlight-color: #bb86fc;
        }}

        body {{
            font-family: 'Noto Sans SC', sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: var(--primary-color);
            background-color: var(--background-color);
            max-width: 1200px;
            margin: 0 auto;
        }}

        h1 {{
            color: var(--highlight-color);
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.5em;
            font-weight: 500;
        }}

        .vulnerability {{
            margin: 20px 0;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            overflow: hidden;
            background-color: var(--surface-color);
        }}

        details > summary {{
            padding: 15px;
            background-color: var(--surface-color);
            cursor: pointer;
            list-style: none;
            position: relative;
            font-weight: 500;
            transition: background-color 0.2s;
        }}

        details > summary:hover {{
            background-color: #2a2a2a;
        }}

        details > summary::-webkit-details-marker {{
            display: none;
        }}

        details > summary::after {{
            content: "+";
            position: absolute;
            right: 15px;
            color: var(--highlight-color);
            font-size: 1.2em;
        }}

        details[open] > summary::after {{
            content: "-";
        }}

        .detail-grid {{
            display: grid;
            grid-template-columns: max-content 1fr;
            gap: 10px 20px;
            padding: 15px;
        }}

        .detail-label {{
            font-weight: 500;
            color: var(--highlight-color);
            white-space: nowrap;
        }}

        .detail-value {{
            word-break: break-all;
        }}

        pre {{
            background-color: #1a1a1a;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            white-space: pre-wrap;
            margin: 0;
            font-family: 'Noto Sans SC', sans-serif;
            border: 1px solid var(--border-color);
        }}

        .payload {{
            background-color: rgba(187, 134, 252, 0.2);
            padding: 2px 4px;
            border-radius: 3px;
            font-weight: 500;
            color: var(--highlight-color);
        }}

        .html-tag {{
            color: #4fc3f7;
            font-weight: 500;
        }}

        .meta-info {{
            margin-bottom: 30px;
            background-color: var(--surface-color);
            padding: 15px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
        }}

        .response-content {{
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            padding: 10px;
            background-color: #1a1a1a;
        }}

        .headers {{
            font-family: 'Noto Sans SC', sans-serif;
            white-space: pre;
        }}

        code {{
            color: var(--highlight-color);
            background-color: rgba(187, 134, 252, 0.1);
            padding: 2px 4px;
            border-radius: 3px;
        }}
    </style>
</head>
<body>
    <h1>XSS漏洞扫描报告</h1>
    
    <section class="meta-info">
        <div class="detail-grid">
            <div class="detail-label">扫描时间：</div>
            <div class="detail-value">{timestamp}</div>
            
            <div class="detail-label">检测Payload：</div>
            <div class="detail-value"><span class="payload">{xss_payload1}</span></div>
            
            <div class="detail-label">POST请求漏洞数量：</div>
            <div class="detail-value">{post_count}</div>
            
            <div class="detail-label">GET请求漏洞数量：</div>
            <div class="detail-value">{get_count}</div>
            
            <div class="detail-label">漏洞总数：</div>
            <div class="detail-value">{len(vulnerabilities)}</div>
        </div>
    </section>

    <section>
        <h2>漏洞列表</h2>
        {vuln_list}
    </section>
</body>
</html>'''

    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_template)
    print(f"[+] HTML报告已生成: {os.path.abspath(output_path)}")

def main():
    # 打印启动横幅
    print(BANNER)
    
    parser = argparse.ArgumentParser(description="网站XSS漏洞检测工具")
    parser.add_argument("-u", "--url", required=True, help="目标URL")
    parser.add_argument("-d", "--depth", type=int, default=2, help="爬取深度")
    parser.add_argument("-o", "--output", default="xss_report.html", help="输出报告文件")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="请求超时时间(秒)")
    parser.add_argument("-c", "--cookie", help="设置请求Cookie")
    args = parser.parse_args()
    
    global REQUEST_TIMEOUT
    REQUEST_TIMEOUT = args.timeout
    
    print(f"[*] 开始扫描: {args.url} (深度: {args.depth})")
    start_time = time.time()
    
    # 配置session
    session.headers.update(get_random_headers())
    
    # 执行爬取
    results = crawl(args.url, args.depth, args.cookie)
    print(f"[+] 爬取完成，发现 {len(results['forms'])} 个表单")
    
    # 测试XSS漏洞
    print("[*] 开始XSS漏洞检测...")
    vulnerabilities = []
    reported_fingerprints = set()
    
    # 1. 测试GET参数中的XSS
    for url in tqdm(results['links'], desc="检测GET参数"):
        parsed = urlparse(url)
        if parsed.query:
            result = test_xss_get(url, args.cookie)
            if result and 'error' not in result and result['vulnerable']:
                fp = result['fingerprint']
                if fp not in reported_fingerprints:
                    reported_fingerprints.add(fp)
                    vulnerabilities.append({
                        'url': url,
                        'result': result
                    })
    
    # 2. 测试表单中的XSS
    for form in tqdm(results['forms'], desc="检测表单"):
        malicious_data = {field['name']: xss_payload for field in form['inputs']}
        
        test_form = {
            'action': form['action'],
            'method': form['method'],
            'inputs': [
                {'name': k, 'value': v} 
                for k, v in malicious_data.items()
            ]
        }
        
        result = submit_form(test_form, args.cookie)
        if 'error' not in result and result.get('vulnerable') and result.get('request'):
            fp = result['fingerprint']
            if fp not in reported_fingerprints:
                reported_fingerprints.add(fp)
                vulnerabilities.append({
                    'form': form,
                    'result': result
                })
    
    # 生成报告
    generate_html_report(vulnerabilities, args.output)
    
    if vulnerabilities:
        print(f"\n[+] 发现 {len(vulnerabilities)} 个XSS漏洞")
    else:
        print("\n[-] 未发现XSS漏洞")
    
    print(f"[*] 总耗时: {time.time()-start_time:.2f}秒")

if __name__ == "__main__":
    main()
