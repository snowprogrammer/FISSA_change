import os
import json

# 定义变量
crash, detect, success, silence, change = 0, 0, 0, 0, 0
cycle_attacked = []
faulted_register = []
# 文件路径
model_name = "total_wop_1_multi_bitflip_reg_multi_2"
# total_wop_1_bitflip_1
# total_wop_1_multi_bitflip_reg_2
# total_wop_1_single_bitflip_spatial_2
# total_wop_1_multi_bitflip_reg_multi_2

folder_path = "C:/Users/13383/Desktop/Distribution-2.2/VerifyPIN/VerifyPIN_2_HB+FTL"
path = f"{folder_path}/{model_name}/results"
base_file = f"{folder_path}/{model_name}/results/total_wop_1.json"
# 遍历文件
key_list = []
results = {}
with open(base_file, 'r') as f:
    base_data = json.load(f)["simulation_0"]
for filename in os.listdir(path):
    if filename.startswith("total_wop_") and filename.endswith(".json"):
        with open(os.path.join(path, filename), 'r') as f:
            data = json.load(f)
            for key, value in data.items():
                if key.startswith("simulation_") and data[key] != 'simulation_0':
                        if ('cycle_attacked' in data[key] and 15725 <= int(data[key]["cycle_attacked"].split()[0]) - 1 <= 19389):
                            status_end = value.get("status_end")
                            if status_end == 1:
                                crash += 1
                            elif status_end == 2:
                                detect += 1
                            elif status_end == 3:
                                success += 1
                                if key not in results:
                                    results[key] = {"threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                                                    "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                                                    "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
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
                            elif status_end == 4:
                                for subkey in base_data.keys():
                                    if subkey.startswith('sram/sr') or subkey.startswith('main_ram/mr') or subkey.startswith('storage/st') or subkey.startswith('storage_1/st1'):
                                        if subkey in data[key]:
                                            if base_data[subkey] != data[key][subkey]:
                                                if key not in key_list:
                                                    change += 1
                                                    key_list.append(key) 
                                silence += 1
silence = silence - change
total = crash + detect + success + silence + change
success_rate = (success / total) * 100 if total > 0 else 0
with open(f"{folder_path}/{model_name}/analysis.json", 'w') as f:
    json.dump({
        "crash": crash,
        "detect": detect,
        "success": success,
        "change": change, 
        "silence": silence,
        "success rate": success_rate,
        "results": results
    }, f, indent=4)
