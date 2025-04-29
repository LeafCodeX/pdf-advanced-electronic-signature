"""
@file util.py
@brief Utility module for detecting connected USB flash drives across different operating systems.
"""
import sys
import re
import subprocess


def get_flash_drive_info(force_update: bool = False) -> list[dict[str, str]]:
    """
    @brief Retrieves information about connected USB flash drives.

    @param force_update Unused parameter, reserved for future functionality.
    @return list[dict[str, str]] A list of dictionaries containing device paths, device names, and serial numbers for each detected flash drive.
    """
    flash_drives: list[dict[str, str]] = []

    if sys.platform == "win32":
        import wmi
        wmi_client = wmi.WMI()

        for drive in wmi_client.Win32_DiskDrive():
            if drive.InterfaceType == "USB":
                for partition in drive.associators(wmi_result_class="Win32_DiskPartition"):
                    for logical_disk in partition.associators(wmi_result_class="Win32_LogicalDisk"):
                        if logical_disk.DriveType == 2:
                            flash_drives.append({
                                "devicePath": f"{logical_disk.DeviceID}\\",
                                "deviceName": drive.Caption,
                                "serialNumber": drive.SerialNumber
                            })

    elif sys.platform == "darwin":
        result = subprocess.run(
            ["ioreg", "-r", "-c", "IOUSBHostDevice", "-l"],
            capture_output=True,
            text=True
        )

        filtered_output = "\n".join(line for line in result.stdout.splitlines() if '"USB Device Info"' in line)

        device_re = re.compile(
            r'"USB Device Info" = {.*?"kUSBVendorString"="(?P<deviceName>[^"]+)",.*?"kUSBSerialNumberString"="(?P<serialNumber>[^"]+)",.*?"USB Product Name"="(?P<usbProductName>[^"]+)",.*?}'
        )

        seen_devices: set = set()

        for match in device_re.finditer(filtered_output):
            device_info: dict[str, str] = {
                "devicePath": f'/Volumes/{match.group("deviceName")}/',
                "deviceName": f'{match.group("deviceName")} {match.group("usbProductName")}',
                "serialNumber": match.group("serialNumber")
            }

            device_id = (device_info["deviceName"], device_info["serialNumber"])

            if device_id not in seen_devices:
                flash_drives.append(device_info)
                seen_devices.add(device_id)

    return flash_drives
