import re
import pandas as pd

# 读取日志文件
def read_logs(file_name="logs.txt"):
    with open(file_name, "r") as file:
        return file.readlines()

# 定义正则表达式解析日志
log_pattern = re.compile(r"^(?P<timestamp>[\d\-]+\s[\d:,]+)\s-\s(?P<type>[A-Z]+)\s-\s(?P<message>.+)$")

# 解析日志
def parse_logs(log_lines):
    log_entries = []
    for line in log_lines:
        match = log_pattern.match(line.strip())
        if match:
            log_entries.append(match.groupdict())
    df = pd.DataFrame(log_entries)
    df['timestamp'] = pd.to_datetime(df['timestamp'])  # 转换时间戳为datetime对象
    return df

# 过滤函数
def filter_logs(df, log_type=None, start_time=None, end_time=None, keyword=None):
    """按类型、时间范围或关键词过滤日志"""
    filtered = df
    if log_type:
        filtered = filtered[filtered['type'] == log_type]
    if start_time:
        filtered = filtered[filtered['timestamp'] >= pd.to_datetime(start_time)]
    if end_time:
        filtered = filtered[filtered['timestamp'] <= pd.to_datetime(end_time)]
    if keyword:
        filtered = filtered[filtered['message'].str.contains(keyword, case=False, na=False)]
    return filtered

# 写入到日志文件
def write_to_log_file(filtered_df, output_file="filtered_logs.txt"):
    """将过滤后的日志写回文件"""
    with open(output_file, "w") as file:
        for _, row in filtered_df.iterrows():
            line = f"{row['timestamp']} - {row['type']} - {row['message']}\n"
            file.write(line)

# 主函数
def main(
    log_file="./logs/scan_log.log",
    output_file ="./logs/filtered.log",
    log_type=None,
    start_time=None,
    end_time=None,
    keyword=None
):
    """主入口，带默认参数"""
    log_lines = read_logs(log_file)
    df = parse_logs(log_lines)

    # 过滤日志
    filtered_logs = filter_logs(df, log_type=log_type, start_time=start_time, end_time=end_time, keyword=keyword)

    # 写入过滤结果
    write_to_log_file(filtered_logs, output_file)
    print(f"Filtered logs have been written to {output_file}")

# 示例用法
if __name__ == "__main__":

    # 按类型过滤并输出
    main(log_type="ERROR")

    # # 按时间范围过滤并输出
    # main(start_time="2024-11-24 01:23:07", end_time="2024-11-24 01:23:07", output_file="time_filtered_logs.txt")
    #
    # # 按关键词过滤并输出
    # main(keyword="cipher", output_file="keyword_logs.txt")
