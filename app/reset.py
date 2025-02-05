import os
import threading
import time
import pyfiglet
from pathlib import Path
import ctypes


# Set the directory path
dir_path = 'D:\\Project\Testing\RecoveredData'

# Check for initial directory access
try:
    os.listdir(dir_path)
except PermissionError:
    print("Permission denied. Run the script as administrator or modify file system permissions.")
    exit(1)

# Attempt to set read-only attribute
try:
    ctypes.windll.kernel32.SetFileAttributesW(dir_path, 0x00000001)  # Set read-only attribute
except PermissionError:
    print("Permission denied. Run the script as administrator or modify file system permissions.")
    exit(1)

# Proceed with data recovery logic

global letter, recoveredLocation, available_drives, total_iteration


class Recovery:
    def __init__(self, filetype):
        self.filetype = filetype

    def DataRecovery(self, fileName, fileStart, fileEnd, fileOffSet):
        self._fileName = fileName
        self._fileStart = fileStart
        self._fileEnd = fileEnd
        self._fileOffSet = fileOffSet

        drive = f"\\\\.\\{letter}:"
        fileD = open(drive, "rb")
        size = 512
        byte = fileD.read(size)
        offs = 0
        drec = False
        rcvd = 0

        while byte:
            found = byte.find(self._fileStart)
            if found >= 0:
                drec = True
                print(f'==== Found {self._fileName} at location: ' + str(hex(found + (size * offs))))
                fileN = open(f'{recoveredLocation}\\' + str(rcvd) + f'.{self._fileName}', "wb")
                fileN.write(byte[found:])
                while drec:
                    byte = fileD.read(size)
                    bfind = byte.find(self._fileEnd)
                    if bfind >= 0:
                        fileN.write(byte[:bfind + self._fileOffSet])
                        fileD.seek((offs + 1) * size)
                        print(f'==== Wrote {self._fileName} to location: ' + str(rcvd) + f'.{self._fileName} ====\n')
                        drec = False
                        rcvd += 1
                        fileN.close()
                    else:
                        fileN.write(byte)
            byte = fileD.read(size)
            offs += 1
        fileD.close()


def progress_bar(t_i, c_i, bar_length, fill):
    percent = f"{100 * c_i / float(t_i):.1f}"
    percent = 100 * c_i / float(t_i)
    fill_length = bar_length * c_i // t_i
    bar = fill * fill_length + "-" * (bar_length - fill_length)
    print(f"\rLoading: |{bar}| {percent}%", end="")
    if c_i == t_i:
        print("\nRunning.........")


print("=" * 100)
print(pyfiglet.figlet_format("Data Recovey Tool", font='starwars', justify="center", width=100))
print("=" * 100)

total_iteration = 50

available_drives = [chr(x) + "" for x in range(65, 91) if os.path.exists(chr(x) + ":")]
cwd = Path.cwd()
recoveredLocation = cwd / 'RecoveredData'
recoveredLocation.mkdir(exist_ok=True)
print(f'Recovered data will be saved to {recoveredLocation}')
print(f"Available Drives are: {available_drives}")

pdf = Recovery('pdf')
jpg = Recovery('jpg')
zip = Recovery('zip')
png = Recovery('png')
txt = Recovery('txt')  # Add text file recovery
mp4 = Recovery('mp4')  # Add mp4 video file recovery

while True:
    letter = input("Enter Removable Drive Letter Or 'Exit' to quit the program: ").capitalize()
    if letter == "Exit" or letter == "exit" or letter == "EXIT":
        break
    elif letter[0] in available_drives:
        for i in range(total_iteration + 1):
            progress_bar(total_iteration, i, 15, ">")
            time.sleep(0.1)

        thread1 = threading.Thread(target=pdf.DataRecovery, args=('pdf', b'\x25\x50\x44\x46\x2D', b'\x0a\x25\x25\x45\x4f\x46', 6))
        thread2 = threading.Thread(target=jpg.DataRecovery, args=('jpg', b'\xff\xd8\xff\xe0\x00\x10\x4a\x46', b'\xff\xd9', 2))
        thread3 = threading.Thread(target=zip.DataRecovery, args=('zip', b'\x50\x4b\x03\x04\x14', b'\x50\x4b\x05\x06', 4))
        thread4 = threading.Thread(target=png.DataRecovery, args=('png', b'\x89\x50\x4e\x47', b'\x49\x45\x4e\x44\xae\x42\x60\x82', 8))
        thread5 = threading.Thread(target=txt.DataRecovery, args=('txt', b'U', b'U', 0))  # Add thread for text recovery
        thread6 = threading.Thread(target=mp4.DataRecovery, args=('mp4', b'\x00\x00\x00\x18\x2A\x49\x44\x58\x57\x00\x00\x00\x00\x00\x00\x00\x00', b'\x00\x00\x00\x1A\x4D\x44\x41\x54', 0)) 

        startpy = time.time()
        thread1.start()
        thread2.start()
        thread3.start()
        thread4.start()
        thread5.start()  # Start the text recovery thread
        thread6.start()  # Start the mp4 recovery thread
        thread1.join()
        thread2.join()
        thread3.join()
        thread4.join()
        thread5.join()  # Wait for text recovery thread to finish
        thread6.join()  # Wait for mp4 recovery thread to finish
        endpy = time.time()
        print(endpy-startpy)