# Define the file path
file_path = "C:/Users/13383/Desktop/mo_project/digilent_basys3_banks_0.init"

# Open the file in write mode
with open(file_path, "w") as file:
    # Write 2048 lines of 00000000
    for _ in range(1024):
        file.write("00000000\n")