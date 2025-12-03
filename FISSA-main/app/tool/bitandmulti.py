import json
import os

version_name = "v0"

cm_name = "Original"
# Complimentary duplication
# Dynamic duplication
# Hamming code
# Original
# Secded code
# Simple parity
# 文件路径
path_a = fr"D:/New folder/{version_name}/{cm_name}/total_wop_1_bitflip_1/analysis.json"
path_b = fr"D:/New folder/{version_name}/{cm_name}/total_wop_1_multi_bitflip_reg_2/analysis.json"

def extract_combinations(file_path):
    """
    提取 simulation_* 下的组合信息：
    返回 { (cycle_attacked, faulted_register): [simulation_names...] }
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    results = data.get("results", {})
    combo_map = {}

    for sim_name, sim_data in results.items():
        if sim_name.startswith("simulation_") and isinstance(sim_data, dict):
            cycle = sim_data.get("cycle_attacked")
            reg = sim_data.get("faulted_register")
            if cycle is not None and reg is not None:
                combo = (cycle, reg)
                combo_map.setdefault(combo, []).append(sim_name)
    return combo_map

def main():
    if not (os.path.exists(path_a) and os.path.exists(path_b)):
        print("请检查文件路径是否正确。")
        return

    combos_a = extract_combinations(path_a)
    combos_b = extract_combinations(path_b)

    diff_combos = set(combos_b.keys()) - set(combos_a.keys())

    if diff_combos:
        print("B 中存在但 A 中没有的组合如下：\n")
        for combo in sorted(diff_combos):
            sims = combos_b[combo]
            print(f"组合 {combo}:")
            for sim in sims:
                print(f"  - {sim}")
            print()
    else:
        print("B 文件中没有新的组合。")

if __name__ == "__main__":
    main()
