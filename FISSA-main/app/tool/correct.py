import json

# 读取json文件
with open('C:/Users/13383/Desktop/test/Secded code/total_wop_1_single_bitflip_spatial_2/analysis.json', 'r') as f:
    data = json.load(f)

# 初始化计数器
count = 0
list1 = ['sim:/digilent_tb/UUT/ack_s', 'sim:/digilent_tb/UUT/builder_basesoc_state_s', 'sim:/digilent_tb/UUT/main_basesoc_interface0_ram_bus_ack_s', 'sim:/digilent_tb/UUT/main_basesoc_interface1_ram_bus_ack_s', 'sim:/digilent_tb/UUT/main_basesoc_ram_bus_ack_s']
list2 = ['sim:/digilent_tb/UUT/builder_slave_sel_r_s', 'sim:/digilent_tb/UUT/sel_s']

# list1 = ['sim:/digilent_tb/UUT/ack_vote_1', 'sim:/digilent_tb/UUT/ack_vote_2', 'sim:/digilent_tb/UUT/ack_vote_3']
# list2 = ['sim:/digilent_tb/UUT/sel_vote_1', 'sim:/digilent_tb/UUT/sel_vote_2', 'sim:/digilent_tb/UUT/sel_vote_3']

# 遍历字典中的键名为corrects中所有键名开头为simulation_的键
for key in data['corrects']:
    if key.startswith('simulation_'):
        # 检查faulted_register_0和faulted_register_1的值是否在list1和list2中
        if (data['corrects'][key]['faulted_register_0'] in list1 and data['corrects'][key]['faulted_register_1'] in list2) or \
        (data['corrects'][key]['faulted_register_0'] in list2 and data['corrects'][key]['faulted_register_1'] in list1):
            count += 1
        # if (data['corrects'][key]['faulted_register_0'] == data['corrects'][key]['faulted_register_1']):
        #     count += 1
        # if ((data['corrects'][key]['faulted_register_0'] in list1 and data['corrects'][key]['faulted_register_1'] in list1) or \
        # (data['corrects'][key]['faulted_register_0'] in list2 and data['corrects'][key]['faulted_register_1'] in list2)) and (data['corrects'][key]['value_set_0'] == data['corrects'][key]['value_set_1'] and data['corrects'][key]['faulted_register_0'] != data['corrects'][key]['faulted_register_1']):
        #     count += 1
# 输出符合条件的键名数量
print(count)
