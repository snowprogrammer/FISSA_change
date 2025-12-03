import matplotlib.pyplot as plt

# 定义数轴范围
x = range(5900, 21001, 100)

# 绘制数轴
plt.figure(figsize=(12, 2))
plt.plot(x, [0]*len(x), 'k-', linewidth=1)  # 绘制数轴线
plt.ylim(-1, 1)  # 设置上下限范围
plt.xlim(5900, 21000)  # 设置x轴范围
plt.yticks([])  # 去掉y轴刻度
plt.xticks(range(5900, 21001, 1000))  # 设置x轴刻度

# 标注 "injection interval"
plt.plot([5909, 14461], [0, 0], 'r', linewidth=2)  # 画出区间线
plt.text((5909 + 14461) / 2, 0.2, 'injection interval', ha='center', color='r')

# 标注 "cm=1" 点
plt.plot(20989, 0, 'bo')  # 标记点
plt.text(20989, -0.2, 'cm=1', ha='center', color='b')

# 标注 "authen=1" 点
plt.plot(15525, 0, 'go')  # 标记点
plt.text(15525, -0.2, 'authen=1', ha='center', color='g')

# 显示网格线
plt.grid(True, axis='x', linestyle='--', linewidth=0.5)
plt.title('Time Axis with Markers (ns)')
plt.xlabel('Time (ns)')
plt.show()
