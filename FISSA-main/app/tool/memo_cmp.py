import os
import json

# 定义需要查找的键名前缀
prefixes = ['main_ram', 'storage', 'storage_1']

# 初始化结果字典
result = {}

# 遍历指定路径下的所有子文件夹
for root, dirs, files in os.walk('C:/Users/13383/Desktop/test'):
    # 如果当前目录深度大于2（即在子文件夹的子文件夹中）
    if root.count(os.sep) - 'C:/Users/13383/Desktop/test'.count(os.sep) >= 2:
        for file in files:
            # 如果文件名为difference.json
            if file == 'difference.json':
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    # 遍历文件中的所有键名
                    for key in data.keys():
                        # 如果键名以指定的前缀开头
                        for prefix in prefixes:
                            if key.startswith(prefix):
                                # 如果文件路径还没有在结果字典中
                                if file_path not in result:
                                    result[file_path] = []
                                # 将键名添加到结果字典中
                                result[file_path].append(key)

# 将结果字典写入到memory_cmp.json文件中
with open('C:/Users/13383/Desktop/test/memory_cmp.json', 'w') as f:
    json.dump(result, f, indent=4)
