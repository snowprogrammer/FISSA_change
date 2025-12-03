import os

# 指定路径tcl
path = "C:/Users/13383/Desktop/FISSA-main/simu_files/generated_simulations/total/total_wop_1_single_bitflip_spatial_2"
# total_wop_1_bitflip_1
# total_wop_1_multi_bitflip_reg_2
# total_wop_1_multi_bitflip_reg_multi_2
# total_wop_1_single_bitflip_spatial_2
# 文件数量
n = 467  # 你可以根据需要修改这个值

for i in range(1, n+1):
    # 创建文件名
    filename = os.path.join(path, f"s{i}.do")
    
    # 写入内容
    content = f"source {path}/total_wop_{i}.tcl"
    
    with open(filename, 'w') as f:
        f.write(content)