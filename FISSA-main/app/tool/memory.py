import os
import json

# 定义变量
cycle_attacked = []

# 文件路径
model_name = "total_wop_1_single_bitflip_spatial_2"
# total_wop_1_bitflip_1
# total_wop_1_multi_bitflip_reg_2
# total_wop_1_multi_bitflip_reg_multi_2
# total_wop_1_single_bitflip_spatial_2
folder_path = "C:/Users/13383/Desktop/Distribution-2.2/VerifyPIN/VerifyPIN_7_HB+FTL+INL+DPTC+DT+SC"
path = f"{folder_path}/{model_name}/results"
base_file = f"{folder_path}/{model_name}/results/total_wop_1.json"

# 读取基础文件
with open(base_file, 'r') as f:
    base_data = json.load(f)["simulation_0"]

# 遍历文件
key_list = []
results = {}
change = 0
for filename in os.listdir(path):
    if filename.startswith("total_wop_") and filename.endswith(".json"):
        with open(os.path.join(path, filename), 'r') as f:
            data = json.load(f)
            for key, value in data.items():
                if key.startswith("simulation_") and data[key] != 'simulation_0':
                    status_end = value.get("status_end")
                    if status_end in [4]:
                        # 比较RegFilePlugin_regFile/rf0到RegFilePlugin_regFile/rf31 sram/sr0到sram/sr2047

                        # for i in range(32):
                        #     if value.get(f"RegFilePlugin_regFile/rf{i}") != base_data.get(f"RegFilePlugin_regFile/rf{i}"):
                        #         key_list.append(key)
                        #         if key not in results:
                        #             results[key] = {"threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                        #                             "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                        #                             "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
                        #         results[key]["threat"] = value.get("threat")
                        #         results[key]["cycle_attacked"] = value.get("cycle_attacked")
                        #         results[key]["faulted_register"] = value.get("faulted_register")
                        #         results[key]["size_faulted_register"] = value.get("size_faulted_register")
                        #         results[key]["bit_flipped"] = value.get("bit_flipped")
                        #         results[key]["value_set"] = value.get("value_set")
                        #         results[key]["faulted_register_0"] = value.get("faulted_register_0")
                        #         results[key]["size_faulted_register_0"] = value.get("size_faulted_register_0")
                        #         results[key]["bit_flipped_0"] = value.get("bit_flipped_0")
                        #         results[key]["value_set_0"] = value.get("value_set_0")
                        #         results[key]["faulted_register_1"] = value.get("faulted_register_1")
                        #         results[key]["size_faulted_register_1"] = value.get("size_faulted_register_1")
                        #         results[key]["bit_flipped_1"] = value.get("bit_flipped_1")
                        #         results[key]["value_set_1"] = value.get("value_set_1")
                        #         break
                        for j in range(2048):
                            if value.get(f"sram/sr{j}") != base_data.get(f"sram/sr{j}"):
                                key_list.append(key)
                                if key not in results:
                                    results[key] = {"status_end": None, "threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                                                    "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                                                    "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
                                    if status_end == 4:
                                        change = change + 1
                                results[key]["status_end"] = value.get("status_end")
                                results[key]["threat"] = value.get("threat")
                                results[key]["cycle_attacked"] = value.get("cycle_attacked")
                                results[key]["faulted_register"] = value.get("faulted_register")
                                results[key]["size_faulted_register"] = value.get("size_faulted_register")
                                results[key]["bit_flipped"] = value.get("bit_flipped")
                                results[key]["value_set"] = value.get("value_set")
                                results[key]["faulted_register_0"] = value.get("faulted_register_0")
                                results[key]["size_faulted_register_0"] = value.get("size_faulted_register_0")
                                results[key]["bit_flipped_0"] = value.get("bit_flipped_0")
                                results[key]["value_set_0"] = value.get("value_set_0")
                                results[key]["faulted_register_1"] = value.get("faulted_register_1")
                                results[key]["size_faulted_register_1"] = value.get("size_faulted_register_1")
                                results[key]["bit_flipped_1"] = value.get("bit_flipped_1")
                                results[key]["value_set_1"] = value.get("value_set_1")
                                break
                        for k in range(2048):
                            if value.get(f"main_ram/mr{k}") != base_data.get(f"main_ram/mr{k}"):
                                key_list.append(key)
                                if key not in results:
                                    results[key] = {"status_end": None, "threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                                                    "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                                                    "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
                                    if status_end == 4:
                                        change = change + 1
                                results[key]["status_end"] = value.get("status_end")
                                results[key]["threat"] = value.get("threat")
                                results[key]["cycle_attacked"] = value.get("cycle_attacked")
                                results[key]["faulted_register"] = value.get("faulted_register")
                                results[key]["size_faulted_register"] = value.get("size_faulted_register")
                                results[key]["bit_flipped"] = value.get("bit_flipped")
                                results[key]["value_set"] = value.get("value_set")
                                results[key]["faulted_register_0"] = value.get("faulted_register_0")
                                results[key]["size_faulted_register_0"] = value.get("size_faulted_register_0")
                                results[key]["bit_flipped_0"] = value.get("bit_flipped_0")
                                results[key]["value_set_0"] = value.get("value_set_0")
                                results[key]["faulted_register_1"] = value.get("faulted_register_1")
                                results[key]["size_faulted_register_1"] = value.get("size_faulted_register_1")
                                results[key]["bit_flipped_1"] = value.get("bit_flipped_1")
                                results[key]["value_set_1"] = value.get("value_set_1")
                                break
                        for l in range(16):
                            if value.get(f"storage/st{l}") != base_data.get(f"storage/st{l}"):
                                key_list.append(key)
                                if key not in results:
                                    results[key] = {"status_end": None, "threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                                                    "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                                                    "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
                                    if status_end == 4:
                                        change = change + 1
                                results[key]["status_end"] = value.get("status_end")
                                results[key]["threat"] = value.get("threat")
                                results[key]["cycle_attacked"] = value.get("cycle_attacked")
                                results[key]["faulted_register"] = value.get("faulted_register")
                                results[key]["size_faulted_register"] = value.get("size_faulted_register")
                                results[key]["bit_flipped"] = value.get("bit_flipped")
                                results[key]["value_set"] = value.get("value_set")
                                results[key]["faulted_register_0"] = value.get("faulted_register_0")
                                results[key]["size_faulted_register_0"] = value.get("size_faulted_register_0")
                                results[key]["bit_flipped_0"] = value.get("bit_flipped_0")
                                results[key]["value_set_0"] = value.get("value_set_0")
                                results[key]["faulted_register_1"] = value.get("faulted_register_1")
                                results[key]["size_faulted_register_1"] = value.get("size_faulted_register_1")
                                results[key]["bit_flipped_1"] = value.get("bit_flipped_1")
                                results[key]["value_set_1"] = value.get("value_set_1")
                                break
                        for m in range(16):
                            if value.get(f"storage_1/st1{m}") != base_data.get(f"storage_1/st1{m}"):
                                key_list.append(key)
                                if key not in results:
                                    results[key] = {"status_end": None, "threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                                                    "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                                                    "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
                                    if status_end == 4:
                                        change = change + 1
                                results[key]["status_end"] = value.get("status_end")
                                results[key]["threat"] = value.get("threat")
                                results[key]["cycle_attacked"] = value.get("cycle_attacked")
                                results[key]["faulted_register"] = value.get("faulted_register")
                                results[key]["size_faulted_register"] = value.get("size_faulted_register")
                                results[key]["bit_flipped"] = value.get("bit_flipped")
                                results[key]["value_set"] = value.get("value_set")
                                results[key]["faulted_register_0"] = value.get("faulted_register_0")
                                results[key]["size_faulted_register_0"] = value.get("size_faulted_register_0")
                                results[key]["bit_flipped_0"] = value.get("bit_flipped_0")
                                results[key]["value_set_0"] = value.get("value_set_0")
                                results[key]["faulted_register_1"] = value.get("faulted_register_1")
                                results[key]["size_faulted_register_1"] = value.get("size_faulted_register_1")
                                results[key]["bit_flipped_1"] = value.get("bit_flipped_1")
                                results[key]["value_set_1"] = value.get("value_set_1")
                                break                            
# 写入memory.json
with open(f"{folder_path}/{model_name}/memory.json", 'w') as f:
    json.dump({
        "change": change,
        "results": results
    }, f, indent=4)

# 读取total_wop_1.json中的数据
with open(f"{folder_path}/{model_name}/results/total_wop_1.json", 'r') as f:
    data_1 = json.load(f)
    simulation_0_data = data_1.get("simulation_0")

# 初始化difference字典
difference = {}

# 遍历results中的所有total_wop_x.json的文件
for filename in os.listdir(f"{folder_path}/{model_name}/results"):
    if filename.startswith("total_wop_") and filename.endswith(".json"):
        with open(os.path.join(f"{folder_path}/{model_name}/results", filename), 'r') as f:
            data_x = json.load(f)
            for key in results.keys():
                if key in data_x:
                    for sub_key in range(1, 2049):
                        sub_key_name = "sram/sr" + str(sub_key)
                        if data_x[key].get(sub_key_name) != simulation_0_data.get(sub_key_name):
                            if key not in difference:
                                difference[key] = {}
                                difference[key]["status_end"] = results[key].get("status_end")
                            difference[key][sub_key_name] = data_x[key].get(sub_key_name)

                    for sub_key in range(1, 2049):
                        sub_key_name = "main_ram/mr" + str(sub_key)
                        if data_x[key].get(sub_key_name) != simulation_0_data.get(sub_key_name):
                            if key not in difference:
                                difference[key] = {}
                                difference[key]["status_end"] = results[key].get("status_end")
                            difference[key][sub_key_name] = data_x[key].get(sub_key_name)

                    for sub_key in range(1, 17):
                        sub_key_name = "storage/st" + str(sub_key)
                        if data_x[key].get(sub_key_name) != simulation_0_data.get(sub_key_name):
                            if key not in difference:
                                difference[key] = {}
                                difference[key]["status_end"] = results[key].get("status_end")
                            difference[key][sub_key_name] = data_x[key].get(sub_key_name)

                    for sub_key in range(1, 17):
                        sub_key_name = "storage_1/st1" + str(sub_key)
                        if data_x[key].get(sub_key_name) != simulation_0_data.get(sub_key_name):
                            if key not in difference:
                                difference[key] = {}
                                difference[key]["status_end"] = results[key].get("status_end")
                            difference[key][sub_key_name] = data_x[key].get(sub_key_name)                                   
# 将difference字典写入difference.json文件
with open(f"{folder_path}/{model_name}/difference.json", 'w') as f:
    json.dump(difference, f, indent=4)
