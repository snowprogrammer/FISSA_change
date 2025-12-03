import os
import json
import glob

# 初始化结果字典
result_dict = {"count": 0, "details": []}

# 获取所有的json文件
json_files = glob.glob("C:/Users/13383/Desktop/test/Dynamic duplication/total_wop_1_multi_bitflip_reg_multi_2/results/total_wop_*.json")
list = ['sim:/digilent_tb/UUT/builder_done', 'sim:/digilent_tb/UUT/builder_csr_bankarray_sel_r', 'sim:/digilent_tb/UUT/builder_grant']
# 遍历所有的json文件
for json_file in json_files:
    with open(json_file, 'r') as f:
        data = json.load(f)
        for key in data:
            if key.startswith("simulation_"):
                if ('faulted_register' in data[key] and data[key]['faulted_register'] not in list) or (('faulted_register_0' in data[key] and data[key]['faulted_register_0'] not in list) \
                    and ('faulted_register_1' in data[key] and data[key]['faulted_register_1'] not in list)):
                    if data[key].get("sram/sr6") == "32'h00010300" and data[key].get("status_end") == 2:
                        result_dict["count"] += 1
                        result_dict["details"].append({
                            "simulation_key": key,
                            "faulted_register_0": data[key].get("faulted_register_0"),
                            "value_set_0": data[key].get("value_set_0"),
                            "faulted_register_1": data[key].get("faulted_register_1"),
                            "value_set_1": data[key].get("value_set_1"),
                            "faulted_register": data[key].get("faulted_register"),
                            "value_set": data[key].get("value_set")
                    })

# 将结果写入新的json文件
with open("C:/Users/13383/Desktop/test/Dynamic duplication/total_wop_1_multi_bitflip_reg_multi_2/memory_alter.json", 'w') as f:
    json.dump(result_dict, f, indent=4)
