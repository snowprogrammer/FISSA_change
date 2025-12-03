import json
import os

# JSON 文件路径
file_path = r"D:/v0/Original/total_wop_1_multi_bitflip_reg_multi_2/analysis.json"

# 加载 JSON 数据
with open(file_path, 'r') as f:
    data = json.load(f)

# 获取 results 数据
results = data.get("results", {})

# 目标寄存器和目标值
target_register = "sim:/digilent_tb/UUT/builder_slave_sel_r"
target_value = "4'b0"

# 初始化计数器
count = 0

# 遍历所有 simulation 开头的键
for key, val in results.items():
    if key.startswith("simulation") and isinstance(val, dict):
        match0 = val.get("faulted_register_0") == target_register and val.get("value_set_0") == target_value
        match1 = val.get("faulted_register_1") == target_register and val.get("value_set_1") == target_value
        if match0 or match1:
            count += 1

# 输出结果
print("符合条件的 simulation 项数量:", count)
