import json
import os

def compare_dicts(d1, d2, prefix=""):
    """递归比较两个字典，返回不同的键路径列表"""
    diffs = []

    all_keys = set(d1.keys()) | set(d2.keys())
    for key in all_keys:
        path = f"{prefix}.{key}" if prefix else key

        if key not in d1:
            diffs.append(f"{path} (missing in simulation_0)")
        elif key not in d2:
            diffs.append(f"{path} (missing in simulation_419)")
        else:
            v1, v2 = d1[key], d2[key]
            if isinstance(v1, dict) and isinstance(v2, dict):
                diffs.extend(compare_dicts(v1, v2, path))
            elif v1 != v2:
                diffs.append(f"{path} (different values)")

    return diffs


def main():
    path = r"D:\1.json"
    if not os.path.exists(path):
        print("❌ 文件未找到：", path)
        return

    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    key1, key2 = "simulation_0", "simulation_419"

    if key1 not in data or key2 not in data:
        print(f"❌ 文件中缺少 '{key1}' 或 '{key2}' 键。")
        return

    diffs = compare_dicts(data[key1], data[key2])

    if not diffs:
        print(f"✅ '{key1}' 和 '{key2}' 完全相同。")
    else:
        print(f"❌ '{key1}' 与 '{key2}' 存在以下差异：")
        for d in diffs:
            print(" -", d)


if __name__ == "__main__":
    main()
