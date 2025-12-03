import os
import json

# 定义变量
crash, detect, success, silence = 0, 0, 0, 0
cycle_attacked = []
faulted_register = []

# 文件路径
path = "/home/zhao/test/Dynamic duplication/total_wop_1_multi_bitflip_reg_2/results"

# 遍历文件
key_list = []
results = {}
for filename in os.listdir(path):
    if filename.startswith("total_wop_") and filename.endswith(".json"):
        with open(os.path.join(path, filename), 'r') as f:
            data = json.load(f)
            for key, value in data.items():
                if key.startswith("simulation_") and not key.endswith("0"):
                    status_end = value.get("status_end")
                    if status_end == 1:
                        crash += 1
                    elif status_end == 2:
                        detect += 1
                    elif status_end == 3:
                        success += 1
                        key_list.append(key)
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
                        silence += 1

total = crash + detect + success + silence
success_rate = (success / total) * 100 if total > 0 else 0
with open("C:/Users/13383/Desktop/test/Dynamic duplication/total_wop_1_multi_bitflip_reg_2/analysis.json", 'w') as f:
    json.dump({
        "crash": crash,
        "detect": detect,
        "success": success,
        "silence": silence,
        "success rate": success_rate,
        "results": results
    }, f, indent=4)
