filename = "file.txt"

# Read the file into a set to remove duplicates
with open(filename, "r") as file:
    lines = set(file.readlines())

# Write the unique lines back to the file
with open(filename, "w") as file:
    for line in lines:
        file.write(line)