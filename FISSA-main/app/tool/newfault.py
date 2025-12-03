import os
import json
# 定义 check_fault_json 函数
def check_fault_json(analysis_file_path, newfault_file_path):
    # 加载 JSON 数据
    def load_json(file_path):
        with open(file_path, 'r') as file:
            return json.load(file)

    # 读取 analysis.json 文件中的数据
    data = load_json(analysis_file_path)

    # 查找 faulted_register 不在 valid_values_list 中的情况
    invalid_faults = {}
    for key, value in data['results'].items():
        # 仅检查以 "simulation_" 开头的键
        if key.startswith("simulation_"):
            faulted_register = value.get("faulted_register")
            # 检查 faulted_register 是否不在 valid_values_list 中
            if faulted_register not in valid_values_list:
                invalid_faults[key] = faulted_register

    # 将不符合的情况写入 newfault.json
    with open(newfault_file_path, 'w') as newfault_file:
        json.dump(invalid_faults, newfault_file, indent=4)

    print(f"Invalid faults saved to {newfault_file_path}")

def check_analysis_json(a_folder, b_folder, valid_values_list):
    # a文件夹中analysis.json的路径
    a_file_path = os.path.join(a_folder, 'analysis.json')
    
    # 加载a文件夹中的analysis.json
    with open(a_file_path, 'r') as a_file:
        a_data = json.load(a_file)
    
    # 存储a文件夹中results下以simulation开头的键及其相关信息
    a_simulation_data = {}
    for key, value in a_data['results'].items():
        if key.startswith('simulation'):
            a_simulation_data[key] = {
                'cycle_attacked': value.get('cycle_attacked'),
                'faulted_register': value.get('faulted_register'),
                'bit_flipped': value.get('bit_flipped'),
                'value_set': value.get('value_set'),
                'correspond_time' : 0
            }
    
    # b文件夹中analysis.json的路径
    b_file_path = os.path.join(b_folder, 'analysis.json')
    
    # 加载b文件夹中的analysis.json
    with open(b_file_path, 'r') as b_file:
        b_data = json.load(b_file)
    
    # 记录不满足条件的项
    invalid_entries = {"results": {}}

    # 检查results下的键值
    for key, value in b_data['results'].items():
        if key.startswith('simulation'):
            # 条件1: faulted_register_0 和 faulted_register_1 的值是否在指定列表(valid_values_list)中
            faulted_reg_0_in_list = value.get('faulted_register_0') in valid_values_list
            faulted_reg_1_in_list = value.get('faulted_register_1') in valid_values_list
            
            # 条件2: cycle_attacked的值是否在a文件夹的cycle_attacked值中，且faulted_register的值匹配
            cycle_attacked = value.get('cycle_attacked')
            is_cycle_and_faulted_registers_matched = False
            
            # 遍历a文件夹中的simulation数据，检查cycle_attacked匹配且faulted_register匹配的情况
            for a_key, a_value in a_simulation_data.items():
                if a_value['cycle_attacked'] == cycle_attacked:
                    # 检查 faulted_register_0 或 faulted_register_1 是否与a文件夹中的相应值匹配
                    if ((value.get('faulted_register_0') == a_value['faulted_register'] and value.get('bit_flipped_0') == a_value['bit_flipped'] and value.get('value_set_0') == a_value['value_set']) or
                        (value.get('faulted_register_1') == a_value['faulted_register'] and value.get('bit_flipped_1') == a_value['bit_flipped'] and value.get('value_set_1') == a_value['value_set'])):
                        is_cycle_and_faulted_registers_matched = True
                        a_value['correspond_time'] = a_value['correspond_time'] + 1 
                        break
            
            # 如果不满足上述两个条件之一，记录下来
            if not (faulted_reg_0_in_list and faulted_reg_1_in_list) and not is_cycle_and_faulted_registers_matched:
                invalid_entries["results"][key] = value
    
    # 将不满足条件的项写入newfault.json文件
    newfault_file_path = os.path.join(b_folder, 'newfault.json')
    with open(newfault_file_path, 'w') as newfault_file:
        json.dump(invalid_entries, newfault_file, indent=4)
        # json.dump(a_simulation_data, newfault_file, indent=4)
    print(f"Invalid faults saved to {newfault_file_path}")

# 示例使用，定义一个包含有效值的样本列表
#valid_values_list = ['sim:/digilent_tb/UUT/builder_basesoc_state', 'sim:/digilent_tb/UUT/builder_slave_sel_r', 'sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack', 'sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack', 'sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack']
#valid_values_list = ['sim:/digilent_tb/UUT/builder_basesoc_state', 'sim:/digilent_tb/UUT/builder_basesoc_state_double', 'sim:/digilent_tb/UUT/builder_slave_sel_r', 'sim:/digilent_tb/UUT/builder_slave_sel_r_double', 'sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack', 'sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack_double', 'sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack', 'sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack_double', 'sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack', 'sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack_double']
#valid_values_list = ['sim:/digilent_tb/UUT/ack_vote_1', 'sim:/digilent_tb/UUT/ack_vote_2', 'sim:/digilent_tb/UUT/ack_vote_3', 'sim:/digilent_tb/UUT/sel_vote_1', 'sim:/digilent_tb/UUT/sel_vote_2', 'sim:/digilent_tb/UUT/sel_vote_3']
#valid_values_list = ['sim:/digilent_tb/UUT/ack_h', 'sim:/digilent_tb/UUT/builder_basesoc_state_h', 'sim:/digilent_tb/UUT/builder_slave_sel_r_h', 'sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack_h', 'sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack_h', 'sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack_h', 'sim:/digilent_tb/UUT/sel_h']
#valid_values_list = ['sim:/digilent_tb/UUT/ack_s', 'sim:/digilent_tb/UUT/builder_basesoc_state_s', 'sim:/digilent_tb/UUT/builder_slave_sel_r_s', 'sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack_s', 'sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack_s', 'sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack_s', 'sim:/digilent_tb/UUT/sel_s']
#valid_values_list = ['sim:/digilent_tb/UUT/ack_p', 'sim:/digilent_tb/UUT/sel_p', 'sim:/digilent_tb/UUT/builder_basesoc_state', 'sim:/digilent_tb/UUT/builder_slave_sel_r', 'sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack', 'sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack', 'sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack']
valid_values_list = []
# 替换为你需要的值

bench_name = "v7"
model_name = "Original"
# Complimentary duplication
# Dynamic duplication
# Hamming code
# Original
# Secded code
# Simple parity
# 文件路径
# analysis_file_path = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_bitflip_1/analysis.json"
# newfault_file_path = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_bitflip_1/newfault.json"
# check_fault_json(analysis_file_path, newfault_file_path)

# # 文件路径
# analysis_file_path = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_multi_bitflip_reg_2/analysis.json"
# newfault_file_path = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_multi_bitflip_reg_2/newfault.json"
# check_fault_json(analysis_file_path, newfault_file_path)

a_folder = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_bitflip_1"
b_folder = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_single_bitflip_spatial_2"
check_analysis_json(a_folder, b_folder, valid_values_list)

a_folder = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_multi_bitflip_reg_2"
b_folder = f"C:/Users/13383/Desktop/New folder/{bench_name}/{model_name}/total_wop_1_multi_bitflip_reg_multi_2"
check_analysis_json(a_folder, b_folder, valid_values_list)
