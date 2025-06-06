
from urllib.parse import urlparse

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns


def visualize_report(raw_data, url):
    plt.rcParams['font.sans-serif'] = ['SimHei']  # Windows系统字体
    plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
    try:
        # 解析嵌套数据结构
        vuln_list = []
        for entry in raw_data['data']:
            if entry['type'] == 1:  # 仅处理漏洞数据
                for param_data in entry['value']:
                    for vuln_id, detail in param_data['data'].items():
                        vuln_list.append({
                            'parameter': param_data['parameter'],
                            'vuln_type': detail['title'],
                            'payload': detail['payload'],
                            'dbms': param_data.get('dbms', 'N/A'),
                            'risk_level': _calc_risk_level(detail['title'])
                        })

        df = pd.DataFrame(vuln_list)

        # 漏洞类型分布图
        plt.figure(figsize=(12, 8))
        type_counts = df['vuln_type'].value_counts()
        plt.pie(type_counts,
                labels=type_counts.index,
                autopct='%1.1f%%',
                startangle=90,
                colors=sns.color_palette('Set3'),
                wedgeprops={'edgecolor': 'white'})
        plt.title(f"漏洞类型分布 - {urlparse(url).netloc}\n共发现{len(df)}处漏洞",
                  fontsize=14, pad=20)
        plt.tight_layout()
        plt.savefig('baogao\\vuln_type_distribution.png', dpi=300, bbox_inches='tight')
        # 参数风险矩阵图
        plt.figure(figsize=(14, 10))
        risk_matrix = df.groupby(['parameter', 'risk_level']).size().unstack().fillna(0)
        sns.heatmap(risk_matrix,
                    annot=True,
                    fmt="d",
                    cmap="YlOrRd",
                    linewidths=0.5,
                    cbar_kws={'label': '漏洞数量'})
        plt.title("请求参数风险等级分布", fontsize=14, pad=20)
        plt.xlabel("风险等级", fontsize=12)
        plt.ylabel("请求参数", fontsize=12)
        plt.xticks(rotation=45)
        plt.savefig('baogao\\param_heatmap.png', dpi=300, bbox_inches='tight')
        # 生成HTML报告
        report_html = f"""
        <html>
            <head>
             <meta charset="UTF-8">
                <title>扫描报告 - {urlparse(url).netloc}</title>
                <style>
                    .report {{ max-width: 1200px; margin: 20px auto; padding: 30px; }}
                    .chart {{ margin: 40px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
                    img {{ width: 100%; border-radius: 8px; }}
                    h2 {{ color: #2c3e50; border-bottom: 2px solid #3498db; }}
                </style>
            </head>
            <body>
                <div class="report">
                    <h2>漏洞扫描报告</h2>
                    <p>扫描目标：<code>{url}</code></p>
                    <p>扫描时间：{pd.Timestamp.now().strftime('%Y-%m-%d %H:%M')}</p>

                    <div class="chart">
                        <h3>漏洞类型分布</h3>
                        <img src='vuln_type_distribution.png'>
                    </div>

                    <div class="chart">
                        <h3>参数风险分析</h3>
                        <img src='param_heatmap.png'>
                    </div>

                    <h3>详细漏洞列表</h3>
                    {df[['parameter', 'vuln_type', 'risk_level']].to_html(index=False, classes='dataframe')}
                </div>
            </body>
        </html>
        """
        with open("baogao\\report.html", "w", encoding='utf-8') as f:
            f.write(report_html)

        print("报告生成成功：baogao\\report.html")

    except Exception as e:
        return f"可视化异常：{str(e)}"

def _calc_risk_level(title):
    """根据漏洞类型判断风险等级"""
    if 'time-based' in title.lower():
        return '高危'
    elif 'error-based' in title.lower():
        return '中危'
    elif 'boolean-based' in title.lower():
        return '低危'
    else:
        return '未知'
