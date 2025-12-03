import json
import os
import argparse
import sys

version_name = "v0"

cm_name = "Original"
# Complimentary duplication
# Dynamic duplication
# Hamming code
# Original
# Secded code
# Simple parity

# 默认文件路径（可用命令行参数覆盖）
path_a = fr"C:/Users/13383/Desktop/New folder/{version_name}/{cm_name}/total_wop_1_bitflip_1/analysis.json"
path_b = fr"C:/Users/13383/Desktop/New folder/{version_name}/{cm_name}/total_wop_1_multi_bitflip_reg_multi_2/newfault.json"


def norm_val(x):
    """规范化值为字符串用于比较"""
    if x is None:
        return None
    if isinstance(x, str):
        return x.strip()
    return str(x)

def load_results(path):
    """读取文件并返回 results 字典"""
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data.get("results", {})

def build_a_combos(results_a):
    """构建 A 文件中的 (cycle_attacked, faulted_register) 集合"""
    combos = set()
    for sim_name, sim in results_a.items():
        if not isinstance(sim, dict) or not sim_name.startswith("simulation_"):
            continue
        cycle = norm_val(sim.get("cycle_attacked"))
        reg = norm_val(sim.get("faulted_register"))
        if cycle is not None and reg is not None:
            combos.add((cycle, reg))
    return combos

def find_b_extras(results_b, combos_a):
    """
    找出 B 中有但 A 中没有的组合
    返回列表，每项是一个 dict：
    {
        "simulation": 名称,
        "cycle_attacked": 值,
        "faulted_register_1": 值,
        "faulted_register_0": 值
    }
    """
    extras = []
    for sim_name, sim in results_b.items():
        if not isinstance(sim, dict) or not sim_name.startswith("simulation_"):
            continue

        cycle = norm_val(sim.get("cycle_attacked"))
        reg0 = norm_val(sim.get("faulted_register_0"))
        reg1 = norm_val(sim.get("faulted_register_1"))

        if cycle is None:
            continue

        # 检查是否存在匹配
        matched = False
        for candidate in (reg0, reg1):
            if candidate is None:
                continue
            if (cycle, candidate) in combos_a:
                matched = True
                break

        if not matched:
            extras.append({
                "simulation": sim_name,
                "cycle_attacked": cycle,
                "faulted_register_1": reg1,
                "faulted_register_0": reg0
            })
    return extras

def main():
    if not os.path.exists(path_a) or not os.path.exists(path_b):
        print("❌ 请检查 A/B 文件路径是否正确。")
        return

    results_a = load_results(path_a)
    results_b = load_results(path_b)

    combos_a = build_a_combos(results_a)
    extras = find_b_extras(results_b, combos_a)

    # 输出路径（和 B 的 analysis.json 同目录）
    output_path = os.path.join(os.path.dirname(path_b), "compare.json")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(extras, f, indent=4, ensure_ascii=False)

    print(f"✅ 比较完成，结果已写入：{output_path}")
    print(f"共发现 {len(extras)} 条 B 独有的组合。")

if __name__ == "__main__":
    main()