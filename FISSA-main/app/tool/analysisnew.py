import os
import json

# 定义变量
crash, detect_hw, detect_sw_c, detect_sw_n, success_c, success_n, correct_hw, silence, change = 0, 0, 0, 0, 0, 0, 0, 0, 0
cycle_attacked = []
faulted_register = []
reg_list = ['sim:/digilent_tb/UUT/builder_done', 'sim:/digilent_tb/UUT/builder_csr_bankarray_sel_r', 'sim:/digilent_tb/UUT/builder_grant']
#因仿真时间不一致，某些sram的值会改变
#---------------------------------------------------------------------------------------
# 定义 X 的范围
values = []
# 使用列表推导式创建 'sram/srX' 的列表
sram_list = [f'sram/sr{X}' for X in values]
#---------------------------------------------------------------------------------------
# 文件路径
model_name = "total_wop_1_multi_bitflip_reg_multi_2"
# total_wop_1_bitflip_1
# total_wop_1_multi_bitflip_reg_2
# total_wop_1_single_bitflip_spatial_2
# total_wop_1_multi_bitflip_reg_multi_2

folder_path = "D:/New folder/v0/Simple parity"
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
                    # if (model_name == "total_wop_1_bitflip_1" and data[key]['faulted_register'] == "sim:/digilent_tb/UUT/builder_done") or (model_name == "total_wop_1_single_bitflip_spatial_2" and (data[key]['faulted_register_0'] in reg_list and data[key]['faulted_register_1'] in reg_list)):    
                    #     if ('faulted_register' in data[key] and data[key]['faulted_register'] in list) or (('faulted_register_0' in data[key] and data[key]['faulted_register_0'] in list) \
                    # or ('faulted_register_1' in data[key] and data[key]['faulted_register_1'] in list)):
                        #if ('cycle_attacked' in data[key] and (not (6205 <= int(data[key]["cycle_attacked"].split()[0]) < 7157)) and (not (8285 <= int(data[key]["cycle_attacked"].split()[0]) < 8421))):
                        #if ('cycle_attacked' in data[key] and (not (6045 <= int(data[key]["cycle_attacked"].split()[0]) < 6381)) and (not (6461 <= int(data[key]["cycle_attacked"].split()[0]) < 6605)) and (not (6693 <= int(data[key]["cycle_attacked"].split()[0]) < 6893)) and (not (7101 <= int(data[key]["cycle_attacked"].split()[0]) < 7365)) and (not (8197 <= int(data[key]["cycle_attacked"].split()[0]) < 8477))):
                            status_end = value.get("status_end")
                            if status_end == 1:
                                crash += 1
                            elif status_end == 2:
                                detect_hw += 1
                            elif status_end == 3:
                            #elif data[key]["sram/sr4"] == 3:
                                detect_sw_c += 1
                            elif status_end == 4:
                                detect_sw_n += 1
                            elif status_end == 5:
                                success_c += 1
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
                            elif status_end == 6:
                                success_n += 1
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
                            elif status_end == 7:
                                if data[key]["sram/sr4"]== "32'h00000301":
                                    success_c += 1
                                    continue
                                for subkey in base_data.keys():
                                    if subkey.startswith('sram/sr') or subkey.startswith('main_ram/mr') or subkey.startswith('storage/st') or subkey.startswith('storage_1/st1'):
                                        if subkey in data[key]:
                                            if base_data[subkey] != data[key][subkey] and subkey not in sram_list:
                                                if key not in key_list:
                                                    change += 1
                                                    correct_hw -= 1
                                                    key_list.append(key) 
                                                #     key_list[key] = {"threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                                                #     "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                                                #     "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
                                                # key_list[key]["threat"] = value.get("threat")
                                                # key_list[key]["cycle_attacked"] = value.get("cycle_attacked")
                                                # key_list[key]["faulted_register"] = value.get("faulted_register")
                                                # key_list[key]["size_faulted_register"] = value.get("size_faulted_register")
                                                # key_list[key]["bit_flipped"] = value.get("bit_flipped")
                                                # key_list[key]["value_set"] = value.get("value_set")
                                                # key_list[key]["faulted_register_0"] = value.get("faulted_register_0")
                                                # key_list[key]["size_faulted_register_0"] = value.get("size_faulted_register_0")
                                                # key_list[key]["bit_flipped_0"] = value.get("bit_flipped_0")
                                                # key_list[key]["value_set_0"] = value.get("value_set_0")
                                                # key_list[key]["faulted_register_1"] = value.get("faulted_register_1")
                                                # key_list[key]["size_faulted_register_1"] = value.get("size_faulted_register_1")
                                                # key_list[key]["bit_flipped_1"] = value.get("bit_flipped_1")
                                                # key_list[key]["value_set_1"] = value.get("value_set_1")
                                correct_hw += 1
                            elif status_end == 8:
                                if data[key]["sram/sr4"]== "32'h00000301":
                                    success_n += 1
                                    continue
                                for subkey in base_data.keys():
                                    if subkey.startswith('sram/sr') or subkey.startswith('main_ram/mr') or subkey.startswith('storage/st') or subkey.startswith('storage_1/st1'):
                                        if subkey in data[key]:
                                            if base_data[subkey] != data[key][subkey] and subkey not in sram_list:
                                                if key not in key_list:
                                                    change += 1
                                                    silence -= 1
                                                    key_list.append(key) 
                                                #     key_list[key] = {"threat": None, "cycle_attacked": None, "faulted_register": None, "size_faulted_register": None, "bit_flipped": None, "value_set": None, \
                                                #     "faulted_register_0": None, "size_faulted_register_0": None, "bit_flipped_0": None, "value_set_0": None, "faulted_register_1": None, \
                                                #     "size_faulted_register_1": None, "bit_flipped_1": None, "value_set_1": None}
                                                # key_list[key]["threat"] = value.get("threat")
                                                # key_list[key]["cycle_attacked"] = value.get("cycle_attacked")
                                                # key_list[key]["faulted_register"] = value.get("faulted_register")
                                                # key_list[key]["size_faulted_register"] = value.get("size_faulted_register")
                                                # key_list[key]["bit_flipped"] = value.get("bit_flipped")
                                                # key_list[key]["value_set"] = value.get("value_set")
                                                # key_list[key]["faulted_register_0"] = value.get("faulted_register_0")
                                                # key_list[key]["size_faulted_register_0"] = value.get("size_faulted_register_0")
                                                # key_list[key]["bit_flipped_0"] = value.get("bit_flipped_0")
                                                # key_list[key]["value_set_0"] = value.get("value_set_0")
                                                # key_list[key]["faulted_register_1"] = value.get("faulted_register_1")
                                                # key_list[key]["size_faulted_register_1"] = value.get("size_faulted_register_1")
                                                # key_list[key]["bit_flipped_1"] = value.get("bit_flipped_1")
                                                # key_list[key]["value_set_1"] = value.get("value_set_1")                                                    
                                silence += 1
with open(f"{folder_path}/{model_name}/analysis.json", 'w') as f:
    json.dump({
        "crash": crash,
        "detect_hw": detect_hw,
        "detect_sw_c": detect_sw_c,
        "detect_sw_n": detect_sw_n,
        "success_c": success_c,
        "success_n": success_n,
        "correct_hw": correct_hw,
        "change": change, 
        "silence": silence,
        "results": results
        #"change condition": key_list
    }, f, indent=4)

