# Define the file path
file_path = "C:/Users/13383/Desktop/mo_project/digilent_basys3_sram.init"

# Open the file in write mode
with open(file_path, "w") as file:
    # Write 2048 lines of 00000000
    for _ in range(2048):
        file.write("00000000\n")

# Print a success message
print(f"2048 lines of 00000000 were successfully written to {file_path}")

# Define the file path
file_path = "C:/Users/13383/Desktop/mo_project/digilent_basys3_main_ram.init"

# Open the file in write mode
with open(file_path, "w") as file:
    # Write 8192 lines of 00000000
    for _ in range(8192):
        file.write("00000000\n")

# Print a success message
print(f"8192 lines of 00000000 were successfully written to {file_path}")