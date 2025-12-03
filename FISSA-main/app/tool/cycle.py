import json
import os
import re
import argparse
import sys

# 默认值（可用 --version / --cm 覆盖）
DEFAULT_VERSION = "v0"
DEFAULT_CM = "Original"

def parse_cycle_value(val):
    """
    从各种可能的 cycle_attacked 表示中提取数值并返回为 int 或 float。
    支持：
      - "2488 ns", "2488ns", "2,488 ns", "2488.0 ns"
      - 直接的数字类型 int/float
    返回数值（int 或 float），解析失败返回 None。
    """
    if val is None:
        return None
    # 直接的数值类型
    if isinstance(val, (int,)):
        return int(val)
    if isinstance(val, float):
        return int(val) if val.is_integer() else val

    if not isinstance(val, str):
        # 其他类型（例如 list/dict），我们无法解析
        return None

    s = val.strip()
    # 正则查找第一个数字（允许千位分隔符逗号、小数点、可选正负号）
    m = re.search(r'[-+]?\d[\d,]*\.?\d*', s)
    if not m:
        return None
    num_str = m.group(0).replace(',', '')
    try:
        if '.' in num_str:
            f = float(num_str)
            return int(f) if f.is_integer() else f
        else:
            return int(num_str)
    except Exception:
        return None

def load_analysis(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ 无法读取或解析 JSON：{path}\n  错误：{e}", file=sys.stderr)
        return None

def extract_cycles_from_results(results):
    """
    遍历 results 中以 simulation_ 开头的条目，提取 cycle_attacked 并解析数值。
    返回：
      cycles_set: set(数值)
      stats: dict 包含计数信息和一些失败样例，用于诊断
    """
    cycles = set()
    total_sim = 0
    parsed_count = 0
    missing_count = 0
    unparsable = []

    for key, val in (results.items() if isinstance(results, dict) else []):
        if not isinstance(key, str) or not key.startswith("simulation_"):
            continue
        total_sim += 1
        cycle_raw = None
        # 常见位置直接取
        if isinstance(val, dict):
            cycle_raw = val.get("cycle_attacked")
        else:
            # 如果 simulation_* 对应不是 dict，记录原始值
            cycle_raw = val

        parsed = parse_cycle_value(cycle_raw)
        if parsed is None:
            missing_count += 1
            # 保存若干失败样例（raw value 与类型）
            if len(unparsable) < 20:
                unparsable.append({"simulation": key, "raw": cycle_raw, "type": type(cycle_raw).__name__})
        else:
            parsed_count += 1
            cycles.add(parsed)

    stats = {
        "total_simulation_entries": total_sim,
        "parsed_count": parsed_count,
        "missing_or_unparsable_count": missing_count,
        "unparsable_examples": unparsable
    }
    return cycles, stats

def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", "-v", default=DEFAULT_VERSION, help="version_name（默认 v1）")
    parser.add_argument("--cm", "-c", default=DEFAULT_CM, help="cm_name（默认 Original）")
    parser.add_argument("--base", "-b", default=None, help="如果想直接指定 base 目录，可用此参数覆盖（例如 C:/.../total_wop_1_multi_bitflip_reg_2）")
    args = parser.parse_args(argv)

    if args.base:
        base_dir = args.base
    else:
        base_dir = fr"D:/New folder/{args.version}/{args.cm}/total_wop_1_multi_bitflip_reg_multi_2"

    path_in = os.path.join(base_dir, "analysis.json")
    path_out = os.path.join(base_dir, "cycle.json")

    if not os.path.exists(path_in):
        print(f"❌ 找不到文件：{path_in}", file=sys.stderr)
        return

    data = load_analysis(path_in)
    if data is None:
        return

    # 有时候 results 不在顶层，先尝试常规位置
    results = data.get("results") if isinstance(data, dict) else None
    if results is None:
        # 诊断输出：展示顶层键，帮助定位结构问题
        if isinstance(data, dict):
            print("⚠️ analysis.json 中未找到顶层 'results' 键。顶层键如下（供检查）：")
            print(list(data.keys())[:50])
        else:
            print("⚠️ analysis.json 解析后不是字典类型。")
        # 仍尝试把整个文件当作 results 处理（容错）
        results = data if isinstance(data, dict) else {}

    cycles_set, stats = extract_cycles_from_results(results)

    # 诊断打印
    print(f"总 simulation_* 条目: {stats['total_simulation_entries']}")
    print(f"成功解析到 cycle 值数: {stats['parsed_count']}")
    print(f"未解析 / 缺失 的条目数: {stats['missing_or_unparsable_count']}")
    if stats['unparsable_examples']:
        print("若干未解析样例（最多 20 个）：")
        for ex in stats['unparsable_examples']:
            print(f"  {ex['simulation']}: raw={ex['raw']} (type={ex['type']})")

    # 去重并升序（按数值大小）
    sorted_cycles = sorted(cycles_set, key=lambda x: float(x))

    # 写入 cycle.json
    try:
        with open(path_out, "w", encoding="utf-8") as f:
            json.dump(sorted_cycles, f, indent=4, ensure_ascii=False)
        print(f"✅ 已写入 {len(sorted_cycles)} 个唯一 cycle 到：{path_out}")
    except Exception as e:
        print(f"❌ 写入文件失败：{e}", file=sys.stderr)

if __name__ == "__main__":
    main()
