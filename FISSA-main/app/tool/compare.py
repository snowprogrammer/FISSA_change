import json
import os

# 定义文件路径
file_path_1 = r"D:/v1/Dynamic duplication/total_wop_1_bitflip_1/results/total_wop_1.json"
file_path_2 = r"D:/v1/Dynamic duplication/total_wop_1_bitflip_1/results/total_wop_1.json"
output_path = r"D:/v1/Dynamic duplication/total_wop_1_bitflip_1/results/diff.json"

# 加载 JSON 数据
def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# 比较两个键的值并返回差异
def compare_json(data1, data2):
    diff = {}
    # 遍历 data1 的每个键值对
    for key in data1:
        if key in data2:
            if data1[key] != data2[key]:
                diff[key] = {'total_wop_1': data1[key], 'total_wop_2': data2[key]}
        else:
            diff[key] = {'total_wop_1': data1[key], 'total_wop_2': None}
    # 检查 data2 中独有的键
    for key in data2:
        if key not in data1:
            diff[key] = {'total_wop_1': None, 'total_wop_2': data2[key]}
    
    return diff

# 主函数
def main():
    # 读取两个 JSON 文件中的数据
    data_1 = load_json(file_path_1)
    data_2 = load_json(file_path_2)

    # 获取指定键 simulation_0 和 simulation_x 的值
    sim_0_data = data_1.get('simulation_0', {})
    sim_diff_data = data_2.get('simulation_31', {})

    # 比较这两个键的值并获取不同的部分
    diff = compare_json(sim_0_data, sim_diff_data)

    # 将差异写入到 diff.json 中
    with open(output_path, 'w') as diff_file:
        json.dump(diff, diff_file, indent=4)

    print(f"Differences saved to {output_path}")

# 执行程序
if __name__ == "__main__":
    main()
