#!/usr/bin/env python
#
# Copyright (c) 2013 Nutanix Inc. All rights reserved.
#
# Author: bharath@nutanix.com
#
# A script that is run on the Hypervisor at first boot after the Nutanix
# installer has laid out the image on the boot disk. This file expects a
# config file in JSON format in a file named first_boot_config.json.

import collections
import copy
import json
import os
import re
import stat
import sys
import time
import uuid
import glob
import shutil
from traceback import format_exc

from consts import *
from firstboot_utils import *
from esx_util import PyvimApi
from log import *

try:
  from distutils.version import LooseVersion
except ImportError:
  # distutils.version is not available in ESXi 5.5
  def LooseVersion(version):
    return map(int, version.split("."))

PCI_DEVICES = []
REBOOT_FOR_PASSTHRU = ["8086:8c02"]
COMMUNITY_EDITION = False

# This is a ridiculous value and is based on no data.
SYNC_TIMEOUT = 60
MAX_ATTEMPTS = 180

# Hax for the missing long in py3.
if sys.version_info >= (3, 0):
  long = int

def log_fatal_callback():
  # On FATAL, marks the firstboot failed before exiting.
  # Create a 'first boot failed' marker.
  run_cmd(["touch", FIRST_BOOT_FAILED_MARKER], fatal=False)
  change_svm_display_name(optional_name='Failed-Install')
  change_esx_display_name(optional_name='Failed-Install')
  change_welcome_screen(clear=True)
  configure_vmk_interface()

def check_phase(phase_name):
  """
  Checks for the existence of a phase marker file.  Returns True
  if exists or False if not.
  """
  return os.path.exists("%s/%s" % (PHASES_BASE, phase_name))

def phase_complete(phase_name):
  """
  Creates a phase marker file.
  """
  run_cmd(["auto-backup.sh"], retry=True, quiet=True)
  run_cmd(["sync; sync; sync"], fatal=False, quiet=True)
  if not os.path.exists(PHASES_BASE):
    os.mkdir(PHASES_BASE)
  with open("%s/%s" % (PHASES_BASE, phase_name), "w") as f:
    os.fsync(f.fileno())
  INFO("Completed phase '%s'" % phase_name)

# Wait for hostd to come up then Create pyVim API object
api = None
retries = 10
while not api and retries:
  try:
    api = PyvimApi(l_info=INFO, l_error=ERROR, l_fatal=ERROR)
  except:
    pass
  if api:
    break
  time.sleep(10)
  retries -= 1

def run_cmd_esxcli(cmd_array, attempts=1, retry_wait=5, fatal=True,
                   timeout=None, quiet=False):
  """
  Wrapper for running esxcli.
  Protects against: ENG-70792. Uses firstboot_utils.run_cmd_new internally.

  Args:
    cmd_array: shell command represented as array. e.g. ["ls", "-l"]
    attempts: Number of attempts of the command.
    fatal: Method exists with FATAL if True
    timeout: time in seconds to wait for a command to complete.
    quiet: If True doesn't print INFO messages.

  Returns:
    (stdout, stderr, return_code), exits with FATAL if fatal=True
  """
  if len(cmd_array) > 1:
    cmd_array.insert(0, "esxcli")
  else:
    cmd_array = ["esxcli " + cmd_array[0]]

  cmd_str = [" ".join(cmd_array)]

  esxcli_failure_retries = 10  # Random number, no data available.
  esxcli_failure_wait_time = 10  # Random number, no data available.

  for _ in range(esxcli_failure_retries):
    (stdout, stderr, return_code) = run_cmd_new(
      cmd_array=cmd_array, attempts=attempts, retry_wait=retry_wait,
      fatal=False, timeout=timeout, quiet=quiet)
    if not return_code:
      return stdout
    else:
      all_output = stdout + stderr
      if "ImportError:" in all_output:
        ERROR("esxcli crashed with ImportError, retrying...")
        time.sleep(esxcli_failure_wait_time)
      else:
        if fatal:
          FATAL("Execution of command %s failed, exit code: %s, stdout: %s, "
                "stderr: %s" % (cmd_str, return_code, stdout, stderr))
        else:
          return stdout
  else:
    if fatal:
      logger = FATAL
    else:
      logger = ERROR
    logger("Unable to recover from esxcli ImportError")

def reboot_host(fatal=False):
  """
  This function saves the esx state and force reboot of the host.
  Args:
    fatal: If True, run_cmd will raise exception in case of error.
        Else, any error is ignored.
  """
  run_cmd(["sync"], timeout=SYNC_TIMEOUT, fatal=False)
  run_cmd(["sleep 10 && reboot 1>2 2>/dev/null &"], fatal=fatal)

def update_boot_cfg(module_name, remove=False, bootbank="bootbank"):
  """
  This function will add or remove a module from boot.cfg from the specified
  bootbank.
  """
  boot_lines = []
  boot_cfg_path = "/%s/boot.cfg" % bootbank
  with open(boot_cfg_path) as fd:
    for line in fd:
      line = line.strip()
      if len(line) == 0:
        continue
      p = line.find("=")
      if p < 0:
        FATAL("ESXi boot.cfg has unexpected format: missing '='")
      boot_lines.append([line[:p], line[p+1:]])

  for line in boot_lines:
    key, value = line
    if key == "modules":
      if remove:
        # Remove module
        if module_name in value:
          line[1] = line[1].replace(" --- %s" % module_name, "")
      else:
        # Add module
        if module_name not in value:
          line[1] += " --- %s" % module_name

  with open(boot_cfg_path, "w") as fd:
    for key, value in boot_lines:
      fd.write("%s=%s\n" % (key, value))

  if remove:
    try:
      os.remove("/%s/%s" % (bootbank, module_name))
    except:
      pass

def monitor_svm_power_state(new_power_state, timeout=None):
  """
  Monitors the SVM power state in a loop and waits until
  requested power state is fulfilled
  """
  count = 0
  start_time = int(time.time())
  while(1):
    if (timeout and ((int(time.time()) - start_time) > timeout)):
      FATAL("SVM failed to switch to a power state of [%s]" %
                (new_power_state,) + "within a %ss timeout window" % timeout)
    power_state = api.get_vm_power_state(api.svm)
    if (power_state == new_power_state):
      INFO("Svm power state is now %s" % new_power_state)
      break
    INFO("Waiting for power state of SVM "
             "to change to %s (attempt %d)" % (new_power_state, count))
    count += 1
    time.sleep(5)

def restart_management_services():
  # Wait for some time for any remaining hostd (esxcli) requests to finish up
  time.sleep(15)
  run_cmd(["/etc/init.d/hostd restart >/dev/null 2>&1"])
  run_cmd(["/etc/init.d/vpxa restart >/dev/null 2>&1"])
  run_cmd(["/etc/init.d/rhttpproxy restart >/dev/null 2>&1"], fatal=False)

  # Sleep for a while to allow hostd to restart.
  time.sleep(10)

def nic_supports_speeds(uplink_speeds, nic):
  """
  Detects whether nic supports any of given list speeds.

  Args:
    uplink_speeds: List of speeds in Mbps.
    nic: Given physical NIC.

  Returns:
    True if nic supports any of the given list of speeds.
    False otherwise.
  """

  for speed in uplink_speeds:
    if int(speed) in nic.supported_speeds:
      return True
  return False

def get_vswitch_links(vswitch, nics):
  """
  Figures out the uplinks in a vswitch.

  Args:
    vswitch: Vswitch dictionary from first boot config.
    nics: List of nics to be considered for the vswitch with nic details.

  Returns:
    Tuple containing the list of uplinks and remaining nics.

  Raises:
    Raise Standard Error if there is no uplinks and uplink_speeds.
  """
  uplinks = []
  remaining_nics = []
  vswitch_uplinks = vswitch.get("uplinks", [])
  uplink_speeds = vswitch.get("uplink_speeds", [])
  if vswitch_uplinks:
    for uplink in vswitch_uplinks:
      for nic in nics:
        if (uplink.lower() == nic.driver.lower() or
            uplink.lower() == nic.mac_addr.lower()):
          if not uplink_speeds or nic_supports_speeds(uplink_speeds, nic):
            uplinks.append(nic.name)
          else:
            remaining_nics.append(nic)
  elif uplink_speeds:
    for nic in nics:
      if nic_supports_speeds(uplink_speeds, nic):
        uplinks.append(nic.name)
      else:
        remaining_nics.append(nic)
  else:
    raise StandardError("A vswitch must have uplinks or uplink speeds")
  return uplinks, remaining_nics

def nics_to_names(nics):
  return [nic.name for nic in nics]

def nics_by_speed(nics):
  """
  Group nics by speed

  Returns:
    a dict of: speed as key, list of nics as value
  """
  # Create new dict keyed off of link-speed with value being a list of vmnics
  # with that link-speed.
  link_speed_dict = collections.defaultdict(list)
  for nic in nics:
    link_speed_dict[nic.max_link_speed].append(nic)
  return link_speed_dict

# team_policy_*
# Args: nics: list of nics to use
# Returns: list of active nics, list of standby nics
def team_policy_fastest_ports(nics):
  """
  Set fastest ports as active
  eg. Set 10G ports as active and 1G ports as standby
  """
  nic_speeds = nics_by_speed(nics)
  max_speed = max(nic_speeds.keys())
  active = nic_speeds[max_speed]
  standby = []
  for speed, nic_list in nic_speeds.items():
    if speed != max_speed:
      standby.extend(nic_list)
  return active, standby

def team_policy_phoenix_fallback(nics):
  """
  Use active_nic in phoenix as active
  only available when P_LIST.hypervisor_mac presents
  """
  assert getattr(P_LIST, "hypervisor_mac", None), (
      "this method requires a valid P_LIST.hypervisor_mac")
  active = []
  standby = []
  for nic in nics:
    if P_LIST.hypervisor_mac.lower() == nic.mac_addr.lower():
      active.append(nic)
    else:
      standby.append(nic)
  return active, standby

def team_policy_first_fastest(nics):
  """
  Use the first fastest port with uplink as active
  Note: this is the default behavior for
        - DEFAULT_VSWITCH if system is not imaged via foundation
        - other vswitches
        this implementation will also guarantee the active list not empty
  """
  nic_speeds = nics_by_speed(nics)
  active = []
  standby = []
  for speed, nic_list in nic_speeds.items():
    for nic in nic_list:
      if not active:
        active = [nic]
        continue
      if nic.link_up and active[0].max_link_speed < nic.max_link_speed:
        standby.extend(active)
        active = [nic]
        continue
      standby.append(nic)
  return active, standby

def team_policy_all(nics):
  """
  Use all nics as active nic, sorted by speed
  """
  nic_speeds = nics_by_speed(nics)
  active = []
  standby = []
  for speed in sorted(nic_speeds.keys(), reverse=True):
    active.extend(nic_speeds[speed])
  return active, standby

def team_policy_default_vswitch(nics):
  """
  Configure the DEFAULT_VSWITCH and test callback if imaged with foundation
  """
  INFO("Searching for NICs which can reach monitoring url: %s"
       % P_LIST.monitoring_url_root)
  INFO("In cases where a NIC is unable to reach the monitoring url "
       "no logs will be returned. This may take several minutes")

  # Use the working port from phoenix.
  if getattr(P_LIST, "hypervisor_mac", None):
    active, standby = team_policy_phoenix_fallback(nics)
    api.set_vswitch_nicTeaming_policy(
        DEFAULT_VSWITCH,
        active_nics=nics_to_names(active),
        standby_nics=nics_to_names(standby))

    # ENG-200431: Restart vmk interface after changing the teaming policy.
    restart_vmk_interface()
    if monitoring_callback("nic_test_fallback_port", retries=5, timeout=1):
      INFO("Configured teaming policy with phoenix port")
      return active, standby
  else:
    # fallback to team fastest nics.
    active, standby = team_policy_fastest_ports(nics)
    api.set_vswitch_nicTeaming_policy(
        DEFAULT_VSWITCH,
        active_nics=nics_to_names(active),
        standby_nics=nics_to_names(standby))

    restart_vmk_interface()
    if monitoring_callback("nic_test_fastest_ports", retries=5, timeout=1):
      INFO("Configured teaming policy with fastest ports")
      return active, standby

  ERROR("No NIC found that could reach the monitoring server")
  # bond all port, and good luck :(
  return team_policy_all(nics)

def configure_vswitches(passthru_nics=None):
  """
  Configures the vSwitch settings on the ESXi host.

  Expects a vswitches object in first_boot_config in the following format:

  vswitches : [
    {
      "name" : <name of vswitch>,
      "uplinks" : list of uplinks, can be specified by MAC or driver,
      "mtu" : <optional, must be an integer>,
      "port_groups" : [
        {
          "name" : <name of port-group>,
          "vlan_tag" : <optional vlan tag as an integer between 0-4095 >,
          "backplane_network": <boolean. If True, this is cvm backplane n/w PG>,
          "vmkernel_nic" :
             {
               "ip" : <ip>,
               "netmask" : <netmask>
             } // Only one VMKernel NIC allowed per port group.
        }, more port_group configs
      ]
    }, more vswitch configs
  ]

  The following is the old behaviour, still maintained in the absence
  of the above specified json:
  - Associate all physical nics to vSwitch0
  - Create vSwitchNutanix
  - Create port-group vmk-svm-iscsi-pg --> vSwitchNutanix
  - Create port-group svm-iscsi-pg --> vSwitchNutanix
  - Assign IP address for vmk-svm-iscsi-pg
  - Set up NIC Teaming Policy

  Before we configure the vswitches, we need to ensure:
  1. Esx has by default vSwitch0 with port groups Management Network and
     VM Network, so before calling this method we already configured vmk0
     (vmkernel) interface with host ip for Management Network in vSwitch0.
     We still have port group VM Network but its not configured. By default
     all nics are assigned to vSwitch0 as uplink. Thats why there must be a
     vSwitch0 present with atleast one NIC attached to it.
  2. A NIC should be present in only one vswitch.
  3. Portgroups are global i.e. two switches can't have same portgroups. If
     other than Management and VM Network portgroups are repeated then it will
     throw error.
  Args:
    passthru_nics: List of addresses of the nics to be passed through to CVM.
        Address is of the form <vendor_id>:<device_id>:<index>. None of these
        nics will be added to the host vswitch irrespective of the vswitches
        input received by first boot script.
  """
  passthru_nics = passthru_nics or []
  pNic_info = api.list_physical_nics()
  # Remove passthru_nics from the list of nics to be considered for host.
  INFO("Checking for passthrough nics")
  nics_to_remove = []
  for nic in pNic_info:
    bus_addr = pNic_info[nic].pci_addr
    if bus_addr in passthru_nics:
      nics_to_remove.append(nic)

  for nic in nics_to_remove:
    INFO("Removing passthrough nic '%s' from available physical NICs" % nic)
    pNic_info.pop(nic)

  # Remove any USB Ethernet adapter from vSwitch.  Some enterprise servers have
  # the ability to expose their BMC as a USB ethernet device for in-band
  # communication but we certainly don't want that device to be in the primary
  # vSwitch.
  usb_eth_devs = []
  INFO("Checking for USB Ethernet devices.")
  for key, val in sorted(pNic_info.items()):
    if val.driver in ['cdc_ether', 'cdce']:
      usb_eth_devs.append(key)
  for dev in usb_eth_devs:
    INFO("'%s' is a USB Ethernet device. Removing from available physical NICs."
         % dev)
    pNic_info.pop(dev)

  existing_vswitches = api.list_vswitches()
  existing_portgroups = api.list_portgroups()

  vswitches = getattr(P_LIST, "vswitches", None)
  if not vswitches:
    # This is the legacy case and we will assign all NICs to the
    # vSwitch0 itself.
    legacy_port_groups = []
    # If the NOS version is >= Asterix.1 (5.1), bring up eth2 interface.
    if (LooseVersion(getattr(P_LIST, "nos_version", "0")) >=
        LooseVersion(MIN_NOS_VERSION_FOR_NS)):
      legacy_port_groups = [{"name": PG_BP_NET, "vmkernel_nic": {}}]
    vswitches = [
      {
        "name" : DEFAULT_VSWITCH,
        "uplinks" : pNic_info.keys(),
        "port_groups" : legacy_port_groups
      }
    ]
  elif (len(vswitches) == 1 and not vswitches[0].get("uplinks", []) and not
        vswitches[0].get("uplink_speeds", [])):
    # When there is only one vswitch and there are neither uplinks nor uplink
    # speeds, assign all the nics to it.
    vswitches[0]["uplinks"] = pNic_info.keys()
  else:
    # Convert the uplinks specified by driver or mac to names.
    # Raise an error if we detect an uplink specified in multiple vswitches.
    nics = []
    for _, pNic in pNic_info.items():
      nics.append(pNic)

    for vswitch in vswitches:
      if not nics:
        raise StandardError("No nic available for vs %s" % vswitch["name"])
      uplinks, rem_nics = get_vswitch_links(vswitch, nics)
      if not uplinks and vswitch.get("uplink_speeds", []):
        # ENG-103044: Foundation couldn't find any uplink with the given
        # speeds. Fallback to the nic with highest speed.
        max_speed = 0
        for nic in nics:
          max_speed = max(max_speed, (nic.max_link_speed or 0))
        if max_speed not in vswitch["uplink_speeds"]:
          INFO("No nics with speed in %s were found. Using nics "
               "with highest available speed %d"
               % (vswitch["uplink_speeds"], max_speed))
          vswitch["uplink_speeds"].append(max_speed)
          uplinks, rem_nics = get_vswitch_links(vswitch, nics)
      if not uplinks:
        raise StandardError("Could not find any uplinks which could be added "
                            "to vswitch %s" % vswitch["name"])
      vswitch["uplinks"] = uplinks
      nics = rem_nics

  all_vswitch_names = [ vs["name"] for vs in vswitches ]
  if NUTANIX_VSWITCH not in all_vswitch_names:
    vswitches.append(
      {
        "name" : NUTANIX_VSWITCH,
        "uplinks" : [],
        "port_groups" : [
          {
            "name" : "vmk-svm-iscsi-pg",
            "vmkernel_nic" :
              {
                 "ip" : "192.168.5.1",
                 "netmask" : "255.255.255.0"
              }
          },
          {
             "name" : "svm-iscsi-pg",
             "vmkernel_nic" : {}
          }
        ]
      }
    )

  if DEFAULT_VSWITCH not in all_vswitch_names:
    raise StandardError("%s missing in vswitches config" % DEFAULT_VSWITCH)
  for vswitch in vswitches:
    vs_name = vswitch["name"]
    INFO("Configuring vswitch %s" % vs_name)
    if vs_name not in existing_vswitches:
      api.create_vswitch(vs_name)
    if vswitch.get("mtu"):
      if not api.set_mtu_of_vswitch(vs_name, vswitch.get("mtu")):
        ERROR("Failed to set MTU on '%s'. Please do so manually"
              % vs_name)
    if vswitch["uplinks"]:
      api.set_physical_nics_on_vswitch(vs_name, vswitch["uplinks"])
    if vswitch["port_groups"]:
      for pg in vswitch["port_groups"]:
        if pg["name"] not in existing_portgroups:
          api.create_portgroup(pg["name"], vs_name)
        if pg.get("backplane_network", False):
          if P_LIST.backplane_network_name:
            raise StandardError("Only one portgroup can have "
                                "backplane_network field set")
          P_LIST.backplane_network_name = pg["name"]
        vlan_tag = pg.get("vlan_tag")
        if vlan_tag:
          try:
            vlan_tag = int(vlan_tag)
            if vlan_tag < 0 or vlan_tag > 4095:
              INFO("Invalid VLAN tag '%s' specified for port-group '%s'"
                   % (vlan_tag, pg["name"]))
            else:
              api.assign_portgroup_vlanId(pg["name"], vlan_tag)
          except:
            ERROR("Unable to apply VLAN tag '%s' on port-group '%s'"
                  % (vlan_tag, pg["name"]))
            ERROR("Will continue without it, please configure manually")
            ERROR("The stacktrace is:\n" + format_exc())
        if pg["vmkernel_nic"]:
          vmk = pg["vmkernel_nic"]
          api.create_vmkernel_nic(pg["name"], vmk["ip"], vmk["netmask"])

    if not vswitch["uplinks"]:
      continue

    # Set up NIC teaming policy.  Set the NIC priority in order of
    # max_link_speed followed by vmnic name.  Allow only 1 NIC to be active
    # at a time.
    pNics = {}
    for key, pNic in pNic_info.items():
      if pNic.name in vswitch["uplinks"]:
        pNics[pNic.name] = pNic

    INFO("Will choose among %s for active NIC for switch %s" % (
        pNics.keys(), vs_name))

    nic_names = nics_to_names(pNics.values())
    api.add_physical_nics_to_vswitch(vs_name, nic_names)

    if vs_name == DEFAULT_VSWITCH:
      # Unset NIC teaming policy for port group.
      # ENG-30362: ESX based Haswell platforms Management Network
      # uses 1G interface instead of 10G interface. This is caused
      # by Management Network has it's own nic teaming policy.
      # We set port group policy to None to let them
      # follow the nic teaming policy from DEFAULT_VSWITCH.
      for pg_name in [PG_MGT_NET, PG_VM_NET, PG_BP_NET]:
        if not pg_name in existing_portgroups:
          continue
        pg_spec = existing_portgroups[pg_name]
        pg_spec.policy.nicTeaming.nicOrder = None
        api.update_portgroup(pg_name, pg_spec)
      if P_LIST.monitoring_url_root:
        monitoring_callback("Testing connectivity on all NICs")
        active, standby = team_policy_default_vswitch(pNics.values())
      else:
        active, standby = team_policy_first_fastest(pNics.values())
    else:
      INFO("Not checking for online NICs since no monitoring server is "
           "specified or vswitch '%s' is not the default vswitch '%s'"
           % (vs_name, DEFAULT_VSWITCH))
      active, standby = team_policy_first_fastest(pNics.values())

    # Set NIC teaming policy with active_nics and standby_nics.
    api.set_vswitch_nicTeaming_policy(
        vs_name,
        active_nics=nics_to_names(active),
        standby_nics=nics_to_names(standby))

  monitoring_callback("vSwitch configuration done")
  # vswitch independent configuration follows.

  # Enable vMotion and Management on vmk0.
  api.enable_vmknic_feature("vmk0", 'vmotion')
  api.enable_vmknic_feature("vmk0", 'management')


def get_partition_table(disk_path=""):
  """
  Captures the partition table details of the specified disk and stores it in a
  dictionary.  If a disk is not provided then the disk serving the
  current bootbank is used.
  See http://kb.vmware.com/selfservice/microsites/search.do?
             language=en_US&cmd=displayKC&externalId=1036609
  for information about partedUtil output.
  """
  if not disk_path:
    out = run_cmd(["vmkfstools -P %s" % os.readlink('/bootbank')])
    match = re.search(r"(t10\..*|naa\..*|mpx..*)\n", out,
                      re.MULTILINE | re.DOTALL)
    if match:
      disk_id = match.groups()[0][:-2]
      disk_path = "/dev/disks/%s" % disk_id

  if not os.path.exists(disk_path):
    FATAL("Device path '%s' does not exist" % disk_path)

  p_table = {
              "disk_path":         disk_path,
              "partitions":        [],
              "partition_IDs":     [],
              "num_cylinders":     None,
              "num_heads":         None,
              "sectors_per_track": None,
              "num_sectors":       None,
              "type":              "gpt",
            }
  p_tbl_out = run_cmd(["partedUtil getptbl %s" % disk_path])
  for i,line in enumerate(p_tbl_out.splitlines()):
    if i == 0:
      # gpt or msdos
      p_table["type"] = line
    elif i == 1:
      # Disk geometry attributes
      (p_table["num_cylinders"], p_table["num_heads"],
       p_table["sectors_per_track"], p_table["num_sectors"]) = line.split()
    else:
      # Since dictionaries don't keep order we need to store the partition
      # details in a list to retain the partition-to-sector order in which
      # they're laid out on the specified disk.
      # A partition row will have the following format:
      # part_id, start_sector, end_sector, guid, type, attribute
      if p_table["type"] == "gpt":
        part_id, start, end, guid, desc, part_type = line.split()
      else:
        part_id, start, end, guid, part_type = line.split()
      p_table["partitions"].append("%s %s %s %s %s" %
                                   (part_id, start, end, guid, part_type))
      p_table["partition_IDs"].append(part_id)
  return p_table


def create_partition(part_id=None, size_gb=None, fs_type=None,
                     strict=True, attrib="0", extra_flags=""):
  """
  Creates a partition with the specified ID, size and filesystem type on
  the ESXi boot disk (bootbank).

  If size_gb is not set then creation of the partition will be greedy and
  will occupy the remaining space on disk.

  If strict is set and the amount of remaining space on disk is less than
  the requested partition size then the operation will fail, else it will
  create the partition with the remaining space on disk.
  """
  def align(sector_address):
    """Aligns sector address to 1MB"""
    return int((sector_address + 2048) / 2048 * 2048)

  if not fs_type:
    ERROR("fs_type is a required parameter.")
    return False

  P_LIST.bootbank_ptable = get_partition_table()
  p_table_type = P_LIST.bootbank_ptable["type"]

  if not part_id:
    part_id = max([int(x) for x in P_LIST.bootbank_ptable["partition_IDs"]]) + 1
  elif part_id in P_LIST.bootbank_ptable["partition_IDs"]:
    ERROR("Partition id %s already exists in partition table." % part_id)
    return False

  if fs_type not in FS_GUID_MAP[p_table_type].keys():
    ERROR("Unsupported filesystem type '%s' specified" % fs_type)
    return False

  current_partitions = P_LIST.bootbank_ptable["partitions"]
  _,_,last_used_sector,_,_ = current_partitions[-1].split()
  if p_table_type == "gpt":
    partition_gap = 1
  else:
    partition_gap = 4097
  new_partition_start = int(last_used_sector) + partition_gap

  # Leave some space at the end of the disk.
  total_disk_sectors = int(P_LIST.bootbank_ptable["num_sectors"]) - 4096

  if P_LIST.ptable_end_sector:
    greedy_end = align(int(P_LIST.ptable_end_sector) - 4096)
  else:
    greedy_end = align(total_disk_sectors)

  # If size_gb is not specified, the behavior during creation will be greedy.
  if size_gb:
    size_sectors = int((size_gb * (1024 ** 3) / 512))
    # Align end to 1MB.  The end is inclusive hence the -1.
    requested_end = align(new_partition_start + size_sectors - 2049) - 1
    INFO("Partition size of %s sectors specified" % size_sectors)
  else:
    requested_end = greedy_end
    strict = False
    INFO("Partition size not specified.  Defaulting to use remaining space on "
         "disk: %s sectors" % (requested_end - new_partition_start))

  if requested_end > total_disk_sectors:
    if strict:
      ERROR("Partition size requested exceeds remaining disk space.")
      return False
    else:
      INFO("Not enough space on disk for a partition of %s sectors but strict "
           "flag was not specified so defaulting to using remaining space of %s"
           " sectors." % ((requested_end - new_partition_start),
                         (greedy_end - new_partition_start)))
      requested_end = greedy_end

  disk_path = P_LIST.bootbank_ptable["disk_path"]
  run_cmd([
     'partedUtil setptbl "%s" %s ' %
                                (disk_path, P_LIST.bootbank_ptable["type"])  +
     '"%s" '                       % '" "'.join(current_partitions) +
     '"%s %s %s %s %s"' % (part_id, new_partition_start, requested_end,
                           FS_GUID_MAP[p_table_type][fs_type], attrib)])
  fs_uuid = run_cmd(['vmkfstools -C %s %s "%s:%s"' %
                    (fs_type, extra_flags, disk_path, part_id)]).split()[-1]
  INFO("Created new partition with UUID: %s" % fs_uuid)
  return fs_uuid

def delete_partition(part_id):
  """
  Delete partiton by id.
  """
  P_LIST.bootbank_ptable = get_partition_table()
  disk_path = P_LIST.bootbank_ptable["disk_path"]
  INFO("Deleting partition %s of disk %s." % (part_id, disk_path))
  run_cmd(['partedUtil delete "%s" %s ' % (disk_path, part_id)])
  INFO("Partition %s of disk %s is deleted." % (part_id, disk_path))

  P_LIST.bootbank_ptable = get_partition_table()

def delete_last_partition():
  """
  Delete last partition.
  """
  INFO("Deleting the last partition.")
  P_LIST.bootbank_ptable = get_partition_table()
  disk_path = P_LIST.bootbank_ptable["disk_path"]
  partition_IDs = P_LIST.bootbank_ptable["partition_IDs"]
  if not partition_IDs:
    FATAL("Unable to delete the last partition, no partition exists on"
        " disk %s." % disk_path)
  delete_partition(partition_IDs[-1])
  INFO("The last partition is deleted.")

def configure_host_common():
  """
  This function configures the ESX host. Does the following:
  - Generate certificates used for VCenter communication
  - Configure iscsi
  - Configure vSwitches
  - Allow nfsClient thorugh host firewall
  - Disable vProbes (close port 57007)
  - Disable storageRM service
  - Set advanced options (NFS.HeartBeatFrequency etc..)
  - Configure vmk0 interface
  - Mask IVB CPU if 'Hummer'
  """
  # Only generate certs if a nutanix image was used to image this system
  if P_LIST.hyp_image_path:
    if not check_phase("gen_certificates"):
      INFO("Generate certificates")
      run_cmd(["generate-certificates"])
      restart_management_services()
      global api
      api = PyvimApi(l_info=INFO, l_error=ERROR, l_fatal=FATAL)
      phase_complete("gen_certificates")

  # Configure vSwitches
  if not check_phase("configure_vswitches"):
    configure_vswitches(passthru_nics=P_LIST.passthru_nics)
    phase_complete("configure_vswitches")

  # Open host firewall for sshClient
  if not check_phase("tsm_ssh"):
    api.allow_service_firewall_exception("sshClient")
    api.confMgr.serviceSystem.UpdatePolicy(id='TSM-SSH', policy='on')
    api.confMgr.serviceSystem.Restart(id='TSM-SSH')
    phase_complete("tsm_ssh")

  # Enable ESXi Shell
  if not check_phase("esxi_shell"):
    api.confMgr.serviceSystem.UpdatePolicy(id='TSM', policy='on')
    api.confMgr.serviceSystem.Restart(id='TSM')
    phase_complete("esxi_shell")

  # Open host firewall for nfsClient
  api.allow_service_firewall_exception("nfsClient")

  # Disable vProbes
  api.deny_service_firewall_exception("vprobeServer")

  # Stop and disable storageRM service.
  run_cmd(["/etc/init.d/storageRM", "stop"], fatal=False)
  run_cmd(["chkconfig", "storageRM", "off"], fatal=False)

  # Set advanced options
  net_tcpip_heap_max = 128
  # http://kb.vmware.com/selfservice/microsites/search.do?
  #        language=en_US&cmd=displayKC&externalId=2239
  if P_LIST.hyp_version >= [5, 5, 0]:
    net_tcpip_heap_max = 512
  # Note: all values must be int in current implementation.
  advanced_options = [
      ("Misc.APDHandlingEnable", 0),
      ("NFS.HeartbeatTimeout", 30),
      ("NFS.MaxVolumes", 64),
      ("Net.TcpipHeapSize", 32),
      ("Power.UseCStates", 0),
      ("Net.TcpipHeapMax", net_tcpip_heap_max),
      ("UserVars.SuppressShellWarning", 1),
      # ENG-218271
      ("SunRPC.MaxConnPerIP", 64),
  ]
  if not check_phase("adv_params"):
    for opt_k, opt_v in advanced_options:
      if P_LIST.hyp_version >= [6, 5, 0]:
        # set_advanced_config_option api is broken for 6.5, using esxcli as
        # workaround.
        # opt_k_path: Misc.APDHandlingEnable => /Misc/APDHandlingEnable
        opt_k_path = "/" + "/".join(opt_k.split("."))
        cmd = [
            "system", "settings", "advanced",
            "set", "-o", opt_k_path, "-i", str(opt_v)]
        run_cmd_esxcli(cmd)
      else:
        api.set_advanced_config_option(opt_k, long(opt_v))
    phase_complete("adv_params")

def configure_host_cache(size_in_bytes):
  """
  This function updates the esx.conf with the host cache size that is
  passed in.
  """
  INFO("Customizing the host cache configuration for this host")
  INFO("Datastore path is %s" % P_LIST.datastore_path)
  INFO("Inserting swap dir location in %s" % ESX_CONF_PATH)
  host_cache_swap_dir_cfg_str = '/adv/Mem/HostLocalSwapDir = "%s"' % \
                                  P_LIST.datastore_path
  open(ESX_CONF_PATH, 'a').write("%s\n" % host_cache_swap_dir_cfg_str)
  rand_uuid = str(uuid.uuid4())
  host_cache_str = '/hostCache%s/%s/hostCache/sizeInBytes = "%s"' % \
                     (P_LIST.datastore_path, rand_uuid, size_in_bytes)
  INFO("Inserting host cache config str %s" % host_cache_str)
  open(ESX_CONF_PATH, 'a').write("%s\n" % host_cache_str)
  INFO("Saving configuration")
  run_cmd(["auto-backup.sh"])

def create_vmfs_partition(datastore_name):
  """
  This function creates a VMFS filesystem and datastore.
  """
  # First create the VMFS partition.
  INFO("Creating VMFS partition and mounting it on datastore %s" %
        datastore_name)
  fs_uuid = create_partition(fs_type="vmfs5",
                             extra_flags="-b 1m -S %s" % datastore_name)
  if not fs_uuid:
    FATAL("An error occured while creating the VMFS partition")
  return fs_uuid


def customize_svm_from_template():
  if not check_phase("customize_svm_template"):
    INFO("Customizing SVM vmx from template")
    svm_dst = "/bootbank/svmboot.tar.gz"
    svm_output = "/tmp/svmboot.tar.gz"
    svm_template_tar_gz = os.path.join(FIRSTBOOT_SCRIPTS_PATH_BASE,
                                       "svm_template.tar.gz")

    customize_svm_template_cmd = ["python", CUSTOMIZE_SVM_SCRIPT_PATH,
                                  "-i", svm_template_tar_gz,
                                  "-u", SYSTEM_UUID, "-o", svm_output,
                                  "-d", "INSTALLING", "-n", SVM_NAME]

    if P_LIST.hyp_version >= [6, 7, 0]:
      hw_version = "14"
    elif P_LIST.hyp_version >= [6, 5, 0]:
      hw_version = "13"
    elif P_LIST.hyp_version >= [6, 0, 0]:
      hw_version = "11"
    elif P_LIST.hyp_version >= [5, 5, 0]:
      hw_version = "10"
    else:
      hw_version = None

    if hw_version:
      customize_svm_template_cmd.extend(["--hardware-version", hw_version])

    if P_LIST.backplane_network_name:
      customize_svm_template_cmd.extend(
          ["--backplane-network-name", "'%s'" % P_LIST.backplane_network_name])

    run_cmd(customize_svm_template_cmd)

    try:
      INFO("Deleting %s" % svm_template_tar_gz)
      os.remove(svm_template_tar_gz)  # We are done with this file.
    except OSError:
      pass

    if P_LIST.use_vmfs_datastore:
      INFO("Untarring the svmboot.tar.gz that was created earlier")
      run_cmd(["tar", "-C", P_LIST.datastore_path, "-xvzf", svm_output])
    else:
      run_cmd(["cp", svm_output, svm_dst])
    phase_complete("customize_svm_template")

def get_disk_locations():
  """
  Creates disk_location.json
  """
  out = run_cmd_esxcli(["storage core path list | grep '^sata\.vmhba'"],
                       attempts=5, timeout=(1 * MINUTE))
  disk_dict = {}
  device_identifiers = []
  location = 1

  for disk in sorted(out.splitlines()):
    disk = disk.strip('_')
    if location != 1:
      full_identifier = disk.split('-')[-1]
      device_identifiers.append(full_identifier)

    serial = disk.split("_")[-1]
    disk_dict[serial] = int(location)
    location += 1

def get_disk_locations_ce():
  disk_dict = {}
  device_identifiers = []
  location = 1
  out = run_cmd(["ls /vmfs/devices/disks"])
  
  for disk in out.splitlines():
    if (disk.startswith("vml")):
      continue
    if (":" not in disk):
      for serial in P_LIST.ce_serials:
        if serial in disk:
          device_identifiers.append(disk)
          disk_dict[disk] = location
          location += 1
      for wwn in P_LIST.ce_wwns:
        if (wwn != None and wwn in disk) and (disk not in device_identifiers):
          device_identifiers.append(disk)
          disk_dict[disk] = location
          location += 1
    # We remove esxi host disk from disk available to CVM
   # elif disk[-3:] == ":10":
    #  print(disk[:-3])
     # device_identifiers.remove(disk[:-3])
     # disk_dict.pop(disk[:-3])
     # location -= 1

  with open(DISK_LOCATION_PATH, 'w') as fp:
    fp.write("%s\n" % json.dumps(disk_dict, sort_keys=True, indent=2))
    fp.flush()
    os.fsync(fp.fileno())
  return device_identifiers

class Vmx(object):
  def __init__(self):
    self.__dict = {}

  def load(self, vmx_path):
    """
    Loads vmx file contents into memory for quick manipulations
    """
    with open(vmx_path, 'r') as vmxfile:
      for line in vmxfile:
        try:
          key, val = line.split("=", 1)
          self.__dict[key.strip()] = val.strip().strip('"')
        except:
          pass

  def dump(self, vmx_path):
    """
    Dumps vmx file contents into file
    """
    with open(vmx_path, 'w') as vmxfile:
      for key, val in sorted(self.__dict.items()):
        vmxfile.write('%s = "%s"\n' % (key, val))

  # CE doesn't need pciPassthru we set everything to false
  def set_pci_passthru_false(self):
    self.__pci_passthru = {}
    for key, val in self.__dict.items():
      if key.lower().startswith("pciPassthru"):
        self.__pci_passthru[key] = "false"

  def remove_pci_passthru_devices(self):
    self.__pci_passthru = {}
    for key, val in self.__dict.items():
      if key.lower().startswith("pcipassthru"):
        self.__pci_passthru[key] = val
        del self.__dict[key]

  def restore_pci_passthru_devices(self):
    self.__dict.update(self.__pci_passthru)

  def set_iso(self, iso_path):
    self.__dict["ide0:0.fileName"] = iso_path

  def attach_vmdk(self, vmdk_path):
    self.__dict['scsi0.present']      = "TRUE"
    self.__dict['scsi0:0.present']    = "TRUE"
    self.__dict['scsi0.sharedBus']    = "none"
    self.__dict['scsi0.virtualDev']   = "lsilogic"
    self.__dict['scsi0:0.fileName']   = vmdk_path
    self.__dict['scsi0:0.mode']       = "independent-persistent"
    self.__dict['scsi0:0.deviceType'] = "scsi-hardDisk"

  def create_and_attach_rdm_disks(self, ds_uuid, dev_paths):
    """
    Creates and attaches all available HDDs as RDMs to the SVM
    """
    if COMMUNITY_EDITION:
      # We append scsi controller, since we do not run attach_vmdk() code which appends it otherwise.
      self.__dict['scsi0.present'] = "TRUE"
      self.__dict['scsi0.sharedBus'] = "none"
      self.__dict['scsi0.virtualDev'] = "lsilogic"

    for index, dev in enumerate(dev_paths):
      parts = re.match(r"t10\.ATA_+([^_]+)_+([^_])+", dev)
      if not COMMUNITY_EDITION:
        model = parts.group(1)
      device_path = "/vmfs/devices/disks/%s" % dev
      rdm_path = "/vmfs/volumes/%s/%s" % (ds_uuid, dev)

      # Create RDM
      INFO("Creating RDM mapping for [%s]" % dev)
      run_cmd(["vmkfstools -z %s %s" % (device_path, rdm_path)])

      # Attach to VMX file
      INFO("Attaching RDM disk [%s] to SVM" % dev)
      scsi_dev_id = "scsi0:%d" % (index + 2)
      self.__dict["%s.present"    % scsi_dev_id] = "TRUE"
      self.__dict["%s.fileName"   % scsi_dev_id] = rdm_path
      self.__dict["%s.mode"       % scsi_dev_id] = "independent-persistent"
      self.__dict["%s.deviceType" % scsi_dev_id] = "scsi-hardDisk"
      self.__dict["%s.redo"       % scsi_dev_id] = ""

      # Add a hint for this device for model detection in SVM.
      if not COMMUNITY_EDITION:
        self.__dict["guestinfo.nutanix.disk-%s.model" % scsi_dev_id] = model
      self.__dict["guestinfo.nutanix.disk-%s.path"  % scsi_dev_id] = device_path

def get_cpu_details():
  """
  Returns: Hardware vendor ID
  """
  cmd = ["hardware", "cpu", "list"]
  out = run_cmd_esxcli(cmd)
  vendor_id = re.search(r"Brand:\s*(\w*)",out).group(1)
  cpu_family = re.search(r"Family:\s*(\w*)",out).group(1)
  cpu_model = re.search(r"Model:\s*(\w*)",out).group(1)
  return vendor_id, cpu_family, cpu_model

def get_number_of_cores():
  """
  Returns: Number of core
  """
  cmd = ["hardware", "cpu", "global", "get"]
  out = run_cmd_esxcli(cmd)
  no_cores = re.search(r"CPU Cores:\s*(\w*)",out).group(1)
  return no_cores

def get_cpu_info():
  """
  Returns: list containing information about all cpus.
  Each cpu is a dictionary of information obtained from parsing esxcli.
  """
  cmd = ["--formatter", "csv", "hardware", "cpu", "list"]
  out = run_cmd_esxcli(cmd)
  lines = out.strip().split()
  # cleanup trailing ",".
  lines = [line.rstrip(",") for line in lines]

  # first line is the header with all the fields defined.
  header = lines.pop(0)
  fields = header.split(",")
  fields = [field.lower() for field in fields]

  cpus = []
  for line in lines:
    values = line.split(",")
    cpu = {}
    for field, value in zip(fields, values):
      cpu[field] = value

    cpus.append(cpu)
  return cpus

# TODO: Expand this function to cover VMX template creation.
def configure_svm_resources():
  """
  Sets various resources for the SVM such as CPU and memory allocation.
  """
  if not check_phase("configure_svm_resources"):
    cpus = get_cpu_info()
    if P_LIST.svm_numa_nodes:
      numa_cpu_set = [int(cpu["id"]) for cpu in cpus
                      if int(cpu["node"]) in P_LIST.svm_numa_nodes]
      # AMD-16 - [AMD] Requesting to apply recommended CVM vCPU
      #          allocation changes in Foundation for AMD Naples
      # https://confluence.eng.nutanix.com:8443/display/~david.sheller/
      #       AMD+EPYC+%28Naples%29+Performance+Experiments
      # AMD-24 - [AMD] Requesting to change existing CVM vCPU
      #                allocation applies to AMD Naples only
      vendor_id, cpu_family, cpu_model = get_cpu_details()
      no_cores = get_number_of_cores()
      if (vendor_id == "AuthenticAMD" and
         (no_cores == "16" or no_cores == "24") and
         cpu_family == "23" and int(cpu_model) <= 15):
        # ENG-202605: Adding numa node affinity setting for all platforms with
        # Intel processor and AMD platforms with 8 or 32 core processors only.
        # Since AMD platforms with 16 and 24 core pocessors contains only 4 and
        # 6 cores per numa node respectively but CVM need 8 cores, cores from
        # adjacent numa node also need to be allocated in addition to cores
        # from local numa node.
        svm_numa_node_socket_id = [int(cpu["packageid"]) for cpu in cpus
                          if int(cpu["node"])in P_LIST.svm_numa_nodes]
        for cpu in cpus:
          if int(cpu["node"]) not in P_LIST.svm_numa_nodes:
            numa_adj_node  = int(cpu["node"])
            numa_adj_node_socket_id = int(cpu["packageid"])
            if (svm_numa_node_socket_id[0] == numa_adj_node_socket_id):
              numa_cpu_set.extend([int(cpu["id"]) for cpu in cpus
                                    if int(cpu["node"])== numa_adj_node])
              break
        INFO("AMD Naples NUMA CPU set computed %s" % numa_cpu_set)
        # In the off chance something is messed up with esxcli or with esx itself
        # add a guardrail to prevent: ENG-158419.
        if len(numa_cpu_set) < P_LIST.svm_num_vcpus:
          WARNING("NUMA CPU set computed to %s, which is smaller than number of "
                  "vcpus allocated to CVM %s. Skipping NUMA affinity." %
                  (numa_cpu_set, P_LIST.svm_num_vcpus))
          numa_cpu_set = None
      else:
        numa_cpu_set = None
    else:
      numa_cpu_set = None

    api.set_vm_memory(api.svm,
                      P_LIST.svm_gb_ram,
                      pin_memory=True,
                      memory_affintiy=None)

    reservation_mhz = None
    # ENG-88966, ENG-79819
    # https://portal.nutanix.com/#/page/docs/details?targetId=vSphere-Admin6-AOS-v50:vsp-vsphere-admission-control-setting-r.html
    num_sockets = len(set([cpu["node"] for cpu in cpus]))
    if num_sockets == 1:
      total_mhz_available = sum([int(cpu["corespeed"]) for cpu in cpus])/10 ** 6
      mhz_cap_for_cvm = int(total_mhz_available * .66)
      if mhz_cap_for_cvm < DEFAULT_CVM_CPU_RESERVATION_MHZ:
        reservation_mhz = FALLBACK_CVM_CPU_RESERVATION_MHZ

    cpu_share_level = "high"
    if P_LIST.svm_numa_nodes and not (
        (no_cores == "16" or no_cores == "24")
        and int(cpu_model) <= 15):
      api.set_vm_numa_node_affinity(api.svm, str(P_LIST.svm_numa_nodes[0]))
    api.set_vm_cpu_allocation(api.svm,
                              P_LIST.svm_num_vcpus,
                              num_sockets=1,
                              share_level=cpu_share_level,
                              cpu_affinity=numa_cpu_set,
                              reservation_mhz=reservation_mhz)
    phase_complete("configure_svm_resources")

def extract_svmfactory_iso():
  """
  This function extracts svmfactory.iso from the boot device and stores it
  in the scratch partition. This is needed for legacy systems.
  """
  INFO("Extracting svmfactory.iso from raw boot device.")
  out = run_cmd(["vmkfstools -P %s" % os.readlink('/bootbank')])
  match = re.search(r"(t10\..*|naa\..*|mpx..*)\n", out,
                    re.MULTILINE | re.DOTALL)
  if match:
    disk_id = match.group(1)[:-2]
    boot_disk_path = "/dev/disks/%s" % disk_id
  else:
    FATAL("Could not identify boot device..")

  with open(boot_disk_path) as bd:
    bd.seek(P_LIST.factory_iso_offset, 0)
    bytes_remaining = P_LIST.factory_iso_size
    with open(P_LIST.SVM_FACTORY_ISO_PATH, "w", 0) as iso:
      default_chunk_size = (16 * 1024**2)
      while bytes_remaining:
        if bytes_remaining < default_chunk_size:
          chunk_size = bytes_remaining
        else:
          chunk_size = default_chunk_size
        iso_data = bd.read(chunk_size)
        iso.write(iso_data)
        bytes_remaining -= chunk_size

def deploy_svm_on_vmdk():
  """
  This function creates and customizes the SVM template
  along with the creation of vmdk.
  """

  INFO("Setting FUA bit for local storage")
  api.set_kernel_module_options("libata", "fua=1")
  api.set_kernel_module_options("libata_92", "fua=1")

  svm_base_path = "%s/%s" % (P_LIST.datastore_path, SVM_NAME)

  # Customize SVM from the template.
  customize_svm_from_template()
  os.symlink(P_LIST.SVM_FACTORY_ISO_PATH,
             os.path.join(svm_base_path, "svmfactory.iso"))

  # Further customizations for NX-2K
  vmx_file_path = "%s/%s.vmx" % (svm_base_path, SVM_NAME)
  vmx = Vmx()
  vmx.load(vmx_file_path)

  # Next, create and attach 60 GB vmdk.
  if not check_phase("create_vmdk"):
    vmdk_loc = "%s/%s/%s" % (P_LIST.datastore_path, SVM_NAME, SVM_VMDK_NAME)
    INFO("Creating vmdk at %s for SVM of size %s"
             %(vmdk_loc, SIZE_OF_SVM_VMDK))
    run_cmd(["vmkfstools", "-c", SIZE_OF_SVM_VMDK, "-a",
             "lsilogic", vmdk_loc])
    vmx.attach_vmdk(SVM_VMDK_NAME)
    phase_complete("create_vmdk")

  # Set iso_path to svmfactory.iso
  if not check_phase("image_svm"):
    vmx.set_iso("svmfactory.iso")

  if not P_LIST.storage_passthru:
    # Find and attach all ATA disks to SVM as RDM disks before imaging.
    dev_paths = get_disk_locations()
    if not check_phase("create_rdm_disks"):
      vmx.create_and_attach_rdm_disks(P_LIST.vmfs_uuid, dev_paths)
      phase_complete("create_rdm_disks")

    # Remove PCI-passthrough device during imaging due to NX-2050 conflict.
    vmx.remove_pci_passthru_devices()

  vmx.dump(vmx_file_path)

  # Next, register the SVM with the generated VMX.
  INFO("Registering the SVM")
  api.svm = api.retry_function_until_success(api.register_vm,
                          (os.path.basename(P_LIST.datastore_path),
                           "%s/%s.vmx" % (SVM_NAME, SVM_NAME)))

  configure_svm_resources()

  # Powering on this VM will result in imaging of the vmdk since the
  # CD-ROM is loaded with the svmfactory.iso.
  if not check_phase("image_svm"):
    INFO("Powering on and imaging the SVM")
    api.svm.PowerOn()
    monitor_svm_power_state("poweredOn", timeout=(1 * MINUTE))

    # Monitor for the VM to power-off which implies that the imaging of the
    # SVM is complete.
    monitor_svm_power_state("poweredOff", timeout=(30 * MINUTE))
    INFO("SVM imaging complete")

    if not P_LIST.storage_passthru:
      INFO("Restoring SVM VMX configuration for first boot")
      # Restore PCI-passthrough devices before first boot.
      vmx.restore_pci_passthru_devices()

    # Restore ISO for booting.
    vmx.set_iso(SVM_NAME + ".iso")
    vmx.dump(vmx_file_path)

    # Remove svmfactory.iso as it is no longer needed
    INFO("Removing svmfactory.iso")
    try:
      os.remove(P_LIST.SVM_FACTORY_ISO_PATH)
    except IOError:
      pass

    try:
      os.remove(os.path.join(svm_base_path, "svmfactory.iso"))
    except IOError:
      pass

    phase_complete("image_svm")

  # Power on the SVM.
  INFO("Powering on SVM")
  api.svm.PowerOn()
  monitor_svm_power_state("poweredOn", timeout=(3 * MINUTE))
  INFO("Svm is now powered on")

  # Check for the existence of genesis.out log.  This means the SVM has
  # completed its firstboot tasks such as installing the RPM packages and
  # reboots of the system, so we're not racing to scp these config files.
  run_cmd_on_svm(cmd="ls /home/nutanix/data/logs/genesis.out", attempts=360)

  # Once the SVM is up, we need to scp the factory_config.json and
  # system.cfg on to the SVM. It is possible that the SVM SSH server isn't
  # up yet upon powering on of the SVM. We are going to try scp until it
  # goes through.
  if not check_phase("config_files"):
    config_files = ( "factory_config.json", "phoenix_version",
                     "foundation_version", "hardware_config.json" )
    INFO("SCP configuration files to the SVM")
    for config in config_files:
      scp_files_to_svm(src_path="%s/%s" % (FIRSTBOOT_SCRIPTS_PATH_BASE, config),
                       dest_path=SYSTEM_CONFIG_PATH_ON_SVM)
      run_cmd_on_svm(cmd="sudo mv %s/%s %s "
                         "&& sudo chmod 755 %s "
                         "&& sudo chmod 644 %s/*" %
                   (SYSTEM_CONFIG_PATH_ON_SVM, config,
                    FACTORY_CONFIG_PATH_ON_SVM, FACTORY_CONFIG_PATH_ON_SVM,
                    FACTORY_CONFIG_PATH_ON_SVM))

    # Create ifcfg-eth0 and trasfer it over if svm_ip was provided
    if P_LIST.svm_ip:
      with open('ifcfg-eth0','w') as ifcfg:
        ifcfg.write(IFCFG_ETH0 % (P_LIST.svm_ip,
                                  P_LIST.svm_subnet_mask,
                                  P_LIST.default_gw))
        os.fsync(ifcfg.fileno())

      ip_changed = False
      while not ip_changed:
        scp_files_to_svm(src_path='ifcfg-eth0',
                         dest_path=SYSTEM_CONFIG_PATH_ON_SVM)
        run_cmd_on_svm(cmd="sudo mv %s/ifcfg-eth0 %s && " %
                       (SYSTEM_CONFIG_PATH_ON_SVM,SVM_IFCFG_ETH0_PATH) +
                       "sudo chown root.root %s && sudo chmod 644 %s" %
                       (SVM_IFCFG_ETH0_PATH, SVM_IFCFG_ETH0_PATH))
        run_cmd_on_svm(cmd="sudo sync; sudo sync; sudo sync", fatal=False)
        INFO("Restarting SVM after transferring configuration files")
        run_cmd_on_svm(cmd="sudo reboot")
        time.sleep(10)
        out, _, _ = run_cmd_on_svm(cmd="/sbin/ifconfig eth0", fatal=False)
        if P_LIST.svm_ip in out:
          ip_changed = True
        else:
          ERROR("ifcfg file was not synced to the filesystem properly. "
                "Will retry.")

    if not P_LIST.storage_passthru:
      INFO("Updating host cache config")
      configure_host_cache(ESX_HOST_CACHE_SIZE_IN_BYTES)

      INFO("SCP system.cfg to the SVM")
      scp_files_to_svm(src_path=SYSTEM_CONFIG_PATH,
                       dest_path=SYSTEM_CONFIG_PATH_ON_SVM)
      run_cmd_on_svm(cmd="sudo chmod 644 %s/system.cfg" %
                     SYSTEM_CONFIG_PATH_ON_SVM)

      INFO("SCP disk_location.json to the SVM")
      scp_files_to_svm(src_path=DISK_LOCATION_PATH,
                       dest_path=SYSTEM_CONFIG_PATH_ON_SVM)
      run_cmd_on_svm(cmd="sudo mv %s/disk_location.json %s " %
                     (SYSTEM_CONFIG_PATH_ON_SVM,FACTORY_CONFIG_PATH_ON_SVM) +
                     "&& sudo chmod 644 %s/disk_location.json" %
                     FACTORY_CONFIG_PATH_ON_SVM)
    phase_complete("config_files")

  # Format FIO devices for NOS version < 3.0.4. The partitions
  # on the device will be created at cluster start.
  if all([SVM_VERSION, SVM_VERSION < [3,0,4], P_LIST.fio_detected,
         P_LIST.svm_install_type == 'clean']):
    stargate_disks = True
    while stargate_disks:
      run_cmd_on_svm(cmd="sudo umount /dev/fio[a-z][0-9]",
                     attempts=1, fatal=False)
      time.sleep(30)
      stargate_disks, _, _ = run_cmd_on_svm(
        cmd="sudo lsblk | grep stargate-storage", fatal=False, attempts=1)
    run_cmd_on_svm(cmd="sudo fio-detach /dev/fct[0-9]", attempts=18)
    run_cmd_on_svm(cmd="sudo fio-format -qy -s60% /dev/fct[0-9]", attempts=18)
    run_cmd_on_svm(cmd="sudo fio-attach /dev/fct[0-9]", attempts=18)

  run_cmd_on_svm(cmd="sudo reboot")

def restart_vmk_interface(vmk_name="vmk0"):
  """
  Restarts a given vmk interface.
  Args:
    vmk_name: Name of the vmk interface.
  """
  INFO("Restarting interface %s" % vmk_name)
  base_cmd = ["network", "ip", "interface"]
  # Bring down the interface.
  cmd = base_cmd + ["set", "-e", "false", "-i", vmk_name]
  run_cmd_esxcli(cmd, attempts=3, timeout=MINUTE, fatal=False)
  # Bring up the interface.
  cmd = base_cmd + ["set", "-e", "true", "-i", vmk_name]
  run_cmd_esxcli(cmd, attempts=3, timeout=MINUTE, fatal=False)

def create_svm_vmx_and_attach_rdm_disks_ce():
  """
  This function creates CVM vmx configuration and attaches 
  rdm disks.
  """
  svm_base_path = "%s/%s" % (P_LIST.datastore_path, SVM_NAME)
  vmx_file_path = "%s/%s.vmx" % (svm_base_path, SVM_NAME)
  vmx = Vmx()
  vmx.load(vmx_file_path)
  if not check_phase("create_rdm_disks"):
    dev_paths = get_disk_locations_ce()
    # Attaches SSD with prepared partitions and all remaing HDD disks to the SVM with RDM
    vmx.create_and_attach_rdm_disks(P_LIST.vmfs_uuid, dev_paths)
    vmx.dump(vmx_file_path)
    phase_complete("create_rdm_disks")

def configure_vmk_interface(disable=False, vmk_name="vmk0"):
  """
  This function sets the network configuration for
  the vmk0 interface with provided static information
  or defaults to DHCP
  """
  ifcfg = ["network", "ip", "interface", "ipv4", "set", "-i",
           vmk_name]

  if disable and not P_LIST.host_ip:
    # This will disable all network comm to the ESX host while installation
    # is in progress
    ip = '0.0.0.0'
    nm = '255.255.255.255'
    ifcfg += ["-I", ip, "-N", nm, "-t", "static"]
    run_cmd_esxcli(ifcfg, attempts=5, timeout=MINUTE)
    return

  if P_LIST.host_ip:
    # Static
    ip = P_LIST.host_ip
    nm = P_LIST.host_subnet_mask
    ifcfg += ["-I", ip, "-N", nm, "-t", "static"]
  else:
    # DHCP
    ifcfg += ["-t", "dhcp", "-P", "true"]

  run_cmd_esxcli(ifcfg, attempts=5)

  if getattr(P_LIST, "cvm_vlan_id", None):
    run_cmd(["esxcfg-vswitch", "-p", "'%s'" % PG_MGT_NET, "-v",
             str(P_LIST.cvm_vlan_id), "vSwitch0"], retry=True)

  if P_LIST.default_gw:
    run_cmd(["esxcfg-route", P_LIST.default_gw], retry=True)

  if P_LIST.dns_ip:
    # Use provided DNS server.
    for dns_ip in P_LIST.dns_ip.split(","):
      run_cmd_esxcli(["network", "ip", "dns", "server", "add", "-s",
                      dns_ip], attempts=5, fatal=False)

def change_svm_display_name(optional_name=None):
  """
  Changes the display name of the SVM to indicate to the
  end user that the imaging process has either completed
  or failed
  """
  # If the SVM is not yet registered then return
  if not api.svm:
    return

  if(optional_name):
    svm_display_name = optional_name
  else:
    svm_display_name = "%s-%s-CVM" % (P_LIST.block_id,
                                         P_LIST.node_position)
    # ENG-71388 : Allow override for displayname.
    if hasattr(P_LIST, "cvm_display_name"):
      svm_display_name = P_LIST.cvm_display_name
    if not svm_display_name.startswith("NTNX-"):
      svm_display_name = "NTNX-" + svm_display_name

  if (P_LIST.use_vmfs_datastore):
    monitor_file = None
  else:
    monitor_file = '/bootbank/svmboot.tar.gz'
    m_time_start = os.stat(monitor_file).st_mtime

  # Rename SVM
  api.retry_function_until_success(api.rename_vm, (api.svm, svm_display_name))

  def _wait_for_vmx_change(start_time, max_wait_secs):
    sleep_interval = 5
    attempts = int(max_wait_secs/sleep_interval)
    curr_time = start_time
    while curr_time == start_time and attempts:
      time.sleep(sleep_interval)
      attempts -= 1
      curr_time = os.stat(monitor_file).st_mtime
    if curr_time == start_time:
      # File hasn't changed.
      return False, curr_time
    # File has changed.
    return True, curr_time

  if monitor_file:
    # Give pynfs time to digest changes to VMX file
    modified, last_modified_time = _wait_for_vmx_change(m_time_start, 300)
    if not modified:
      FATAL("Failed to update %s within 5 minutes" % monitor_file)
    # ENG-180717: File has been modified once. It might have been modified
    # before the SVM name change. Wait for another 60 seconds to ensure that
    # pynfs checkpoints the change. If no change has happened in next 60 secs
    # as well, assume the change was already synced in previous attempt.
    _wait_for_vmx_change(last_modified_time, 60)

def change_esx_display_name(optional_name=None):
  """
  Changes the display name of ESX host
  """
  if optional_name:
    hostname = optional_name
  else:
    hostname = "%s-%s" % (P_LIST.cluster_name,
                          P_LIST.node_name)
  INFO("Changing ESX hostname to '%s'" % hostname)
  run_cmd_esxcli(["system", "hostname", "set", "--fqdn", hostname],
                 attempts=5)

def pci_search(vendor_device_id=None):
  """
  Searches a list of PCI devices by vendor:device ID and returns the following
  structure if there is a match found.
     PCI bus addr   Class   vendor/device ID
    ['00:ff:13.6', '0880:', '8086:3c45']
  """
  global PCI_DEVICES
  if not PCI_DEVICES:
    # Discover all PCI devices using lscpi the first time we call pci_search.
    INFO("Enumerating all PCI devices")
    devices = run_cmd(["lspci","-n"], retry=True).splitlines()
    for dev in devices:
      dev = dev.split()
      dev.pop(1)
      # Format will look like:
      # PCI bus addr,  Class,    vendor:device-ID
      # ['00:ff:13.6', '0880:', '8086:3c45']
      PCI_DEVICES.append(dev)

  for dev in PCI_DEVICES:
    if vendor_device_id == dev[2]:
      return dev
  return None

def install_vibs(vib_list, allow_downgrade=True):
  """
  Takes a list of vibs as input and installs them.
  """
  for vib in vib_list:
    # Dont install vib if it is a downgrade
    if not allow_downgrade:
      vibs_info = get_vib_name_version_map(vib)
      downgrade = False
      for name in vibs_info.keys():
        if check_if_downgrade(name, vibs_info[name]):
          downgrade = True
          break
      if downgrade:
        continue

    INFO("Installing vib [%s]" % vib)
    if vib.endswith(".zip"):
      run_cmd_esxcli(["software", "vib", "install",
                      "--maintenance-mode", "-d", "%s" % vib])
    elif ("MegaCli" in vib or "nmlx5" in vib):
      # MegaCli vib is not signed.
      run_cmd_esxcli(["software", "vib", "install",
                      "--maintenance-mode", "--no-sig-check", "-v", "%s" % vib])
    else:
      run_cmd_esxcli(["software", "vib", "install",
                      "--maintenance-mode", "-v", "%s" % vib])

def modify_sshd_config():
  """
  For hosts with misconfigured DNS, ssh may take long time. This function sets
  "UseDNS no" in sshd_config on host.
  """
  sshd_config_file = "/etc/ssh/sshd_config"

  sshd_cfg = []
  with open(sshd_config_file, "rb") as fd:
    lines = fd.read().decode("utf-8").splitlines()
    for line in lines:
      if line.lower().lstrip().startswith("usedns"):
        continue
      sshd_cfg.append(line.strip())
  # Append at the end.
  sshd_cfg.append("UseDNS no\n")

  with open(sshd_config_file, 'wb') as fd:
    data = "\n".join(sshd_cfg)
    fd.write(data.encode("utf-8"))
    # Flush the internal write buffers to os.
    fd.flush()

def set_default_password():
  """
  This function sets the root password.
  """
  INFO("Setting default password")
  encrypted_pass = ("$6$n0zwEgiZ$oQL7W.A4fYXa9WXvex3X1a9vB5xgknJK379mkOH/"
                    "Vibgk4K43tZHSwL6zwT1M/wZfJUslfIwswiPpD9tBReKM0")

  with open("/etc/shadow") as shadow:
    shadow_orig = shadow.read()

  shadow_mod = re.sub(r"root:(.*?):.*?", "root:%s:" % encrypted_pass,
                      shadow_orig)
  with open("/etc/shadow", "w") as shadow:
    shadow.write(shadow_mod)
    os.fsync(shadow.fileno())

def filter_boot_drivers(P_LIST, drivers):
  if not P_LIST.hardware_config:
    return drivers
  node = P_LIST.hardware_config["node"]
  if not node["boot_device"]:
    return drivers
  hba = node["boot_device"].get("controller")
  if not hba:
    return drivers
  if hba.startswith("HBA:1000:005f:"):
    drivers.remove("lsi_msgpt3")
  return drivers

def setup_scratch_attrs(target="/scratch"):
  scratch_path = os.path.join(target, "Nutanix")
  P_LIST.scratch_path = scratch_path
  run_cmd(["mkdir", "-p", scratch_path])

  # We only need vibs once, before firstboot, so, it doesn't matter if we put
  #  them im permanent scratch or tmpfs.
  P_LIST.VIB_PATH_BASE = os.path.join(scratch_path, "vibs")

  # We use this after we have created a permanent scratch partition, so,
  # this is okay.
  P_LIST.SVM_FACTORY_ISO_PATH = os.path.join(scratch_path,
                                             "svmfactory.iso")

def conserve_bootbank_space():
  """
  Conserving space in bootbank by moving large installation files to
  the P_LIST.VIB_PATH_BASE folder (usuallly scratch partition).

  If P_LIST.VIB_PATH_BASE is not a persistent storage, only vibs
  will be relocated.
  """

  INFO("Conserving space in bootbank. Moving vibs to %s" % P_LIST.VIB_PATH_BASE)
  vibs_path = os.path.join(FIRSTBOOT_SCRIPTS_PATH_BASE, "vibs")
  if os.path.exists(vibs_path):
    run_cmd(["mv", vibs_path, P_LIST.VIB_PATH_BASE])

def preserve_nutanix_module():
  """
  Copies nutanix module from bootbank to altbootbank
  """
  if P_LIST.is_secureboot:
    DEBUG("Skip preserving nutanix module in secure boot")
    return
  shutil.copy("/bootbank/nutanix.tgz", "/altbootbank/nutanix.tgz")
  update_boot_cfg("nutanix.tgz", bootbank="altbootbank")

def install_dell_vibs():
  dell_ism_vib = []
  dell_ptagent_vib = []
  if (P_LIST.hardware_config and
      P_LIST.hardware_config["chassis"]["class"].startswith("IDRAC")):
    dell_ism_vib = glob.glob("%s/ISM-Dell*" % P_LIST.VIB_PATH_BASE)
    # Needed for OS to IDRAc passthrough
    if dell_ism_vib and not check_phase("install_dell_ism_vib"):
      INFO("Installing Dell ISM vib")
      install_vibs(dell_ism_vib)
      preserve_nutanix_module()
      phase_complete("install_dell_ism_vib")
      INFO("Rebooting. This may take several minutes")
      run_cmd(["sync"])
      reboot_host()
      sys.exit()

    dell_ptagent_vib = glob.glob("%s/DellPTAgent*" % P_LIST.VIB_PATH_BASE)
    # Needed for Dell NVMe  and LCM support
    if dell_ptagent_vib and not check_phase("install_dell_ptagent_vib"):
      INFO("Installing Dell PTAgent")
      install_vibs(dell_ptagent_vib)
      if P_LIST.hyp_version >= [6, 0, 0]:
        ptagent_config_file = "/scratch/dell/config/PTAgent.config"
      else:
        ptagent_config_file = "/scratch/dell/DellPTAgent/bin/PTAgent.config"
      if not os.path.exists(ptagent_config_file):
        FATAL("Unable to find Dell PTAgent Config file")
      ptagent_ver = get_vib_name_version_map("dellptagent")["dellptagent"]
      if LooseVersion(ptagent_ver) >= LooseVersion("1.9"):
        configure_with_ptacfg_tool = True
      else:
        configure_with_ptacfg_tool = False
      configure_ptagent(ptagent_config_file, configure_with_ptacfg_tool)
      phase_complete("install_dell_ptagent_vib")

  return dell_ptagent_vib + dell_ism_vib

def open_firewall_port(port):
  """
  Opens the given port for outgoing connections by following the steps
  in goo.gl/gkzu9j . This function is written to open non-standard ports
  for Nutanix Automation Framework only and should not be used in
  regular redeployments in the field.

  If port is 8000, this is a no-op.

  This operation is NOT persistent across reboots.
  """
  if port == 8000:
    return
  service_file = "/etc/vmware/firewall/nutanixAutomation.xml"
  new_rule = """<ConfigRoot>

  <service id='9100'>
    <id>nutanix-automation-framework</id>
    <rule id='0000'>
      <direction>outbound</direction>
      <protocol>tcp</protocol>
      <port type='dst'>%s</port>
    </rule>
   <enabled>true</enabled>
   <required>false</required>
  </service>

</ConfigRoot>""" % port
  with open(service_file, "w") as fd:
    fd.write(new_rule)
  run_cmd_esxcli(["network firewall refresh"])
  INFO("Firewall port %s opened" % port)
  return

def check_if_downgrade(vib_name, vib_version):
  vibs_map = get_vib_name_version_map(vib_name)
  installed_version = None
  if vib_name in vibs_map.keys():
    installed_version = vibs_map[vib_name]
  if (installed_version and
      (LooseVersion(installed_version) > LooseVersion(vib_version))):
    return True
  return False

def get_vib_name_version_map(vib_url):
  """
  Returns vib name and version
  """
  vib_details = None
  if vib_url.endswith(".vib"):
    # vib url
    vib_details = run_cmd_esxcli(["software", "sources", "vib", "get",
                                  "-v", vib_url])
  elif vib_url.endswith(".zip"):
    #depot
    vib_details = run_cmd_esxcli(["software", "sources", "vib",
                                  "get", "-d", vib_url])
  else:
    vib_details = run_cmd_esxcli(["software", "vib", "get", "-n",
                                  vib_url], fatal=False)
    if "NoMatchError" in vib_details:
      return {}
  vib_name_version_map = {}
  for vib in vib_details.split("\n\n"):
    lines = vib.splitlines()
    vib_name = lines[1].split(':')[1].strip()
    vib_version = lines[2].split(':')[1].strip().split('-')[0]
    vib_name_version_map[vib_name] = vib_version
  return vib_name_version_map

def change_welcome_screen(clear=False):
  filename = "/etc/vmware/welcome"
  if clear:
    open(filename, "w").close()
  else:
    run_cmd_new(["cp", "%s/welcome_message" % FIRSTBOOT_SCRIPTS_PATH_BASE,
                 filename])
  # Refresh DCUI by killing the current process. This will spawn a new
  # instance. Even if killing the process fails, whenever user sends a
  # keystroke to the login page, it will be refreshed.
  run_cmd_new(["kill $(ps | grep dcui | awk '{print $1}')"], fatal=False)

def store_iavmd_passthru(vmd_file_path, vmd_ids=None):
  """
  Create temporary file that stores VMD information
  designated via vmd_file_path and prepare local.sh
  that will be called upon reboot.
  """

  if vmd_ids is None:
    vmd_ids = []
  with open(vmd_file_path, "w") as vmd_init_f:
    vmd_init_f.write("# *** Autogenerated code by Phoenix ***\n")
    vmd_init_f.write("# __START Enable VMD for Passthrough\n")
    for vmd_id in vmd_ids:
      vmd_init_f.write("vmkchdev -p 0x%s\n" % vmd_id)
      try:
        seg, bus, dev, fn = re.split(r'[:.]', vmd_id)
        seg = str(int(seg, 16))
        bus = str(int(bus, 16))
        dev = str(int(dev, 16))
        fn = str(int(fn, 16))
        v_path = os.path.join('', 'hardware', 'pci', 'seg', seg, 'bus', bus)
        v_path = os.path.join(v_path, 'slot', dev, 'func', fn, 'resetMethod')
      except (ValueError, TypeError):
        message = ("Expected to have segment:bus:dev.function format "
                   "but found value is %s") % vmd_id
        FATAL(message)
      vmd_init_f.write("/sbin/vsish -e set %s 2\n" % v_path)
    vmd_init_f.write("# __END Enable VMD for Passthrough\n")

  if os.path.exists("/etc/rc.local.d/local.sh"):
    # ESXi versions >= 5.1.0
    rc_file = "/etc/rc.local.d/local.sh"
  else:
    # ESXi versions < 5.1.0
    FATAL("It is unexpected to not to have /etc/rc.local.d/local.sh"
          " May be running with ESXi lower than 5.1?")

  with open(rc_file) as f_read:
    current_local_rc = f_read.read()

  with open(vmd_file_path) as vmd_f:
    with open(rc_file, "w") as f_write:
      f_write.write(vmd_f.read())
      f_write.write(current_local_rc)

def install_nic_drivers_with_reboot(drivers_list):
  """
  Installs drivers for nics which require a reboot after installation.
  Args:
    drivers_list: List of tuples of the form
      (vib_name_prefix, nic_list, phase_name,
       allow_downgrade, install_always, driver_name) where
      vib_name_prefix is the prefix of the vib using which it canbe uniquely
          identified,
      nic_list is the list of pci ids of the nics supported by this driver,
      phase_name is the name of the phase for idempotency,
      install_always, if true, will install the vib even if a supported nic
          is not present.
  Returns:
    True if reboot is needed, False otherwise.
  """
  reboot_required = False
  for driver in drivers_list:
    (vib_prefix, nics, phase_name, allow_downgrade, install_always,
     driver_name) = driver
    glob_param = "%s/vibs/%s*" % (FIRSTBOOT_SCRIPTS_PATH_BASE, vib_prefix)
    nic_vib = glob.glob(glob_param)
    nics_present = any(pci_search(nic) for nic in nics)
    if nic_vib and not check_phase(phase_name):
      if nics_present or install_always:
        INFO("Installing %s driver" % driver_name)
        install_vibs(nic_vib, allow_downgrade=allow_downgrade)
        INFO("Installed %s driver successfully" % driver_name)
        phase_complete(phase_name)
      if nics_present:
        if len(nics) == 1:
          INFO("Detected nic with PCI ID: %s" % nics[0])
        reboot_required = True
  return reboot_required

def main():

  if not api:
    message = ("api object is None. This means hostd is not yet up. Please "
               "run python /bootbank/Nutanix/firstboot/esx_first_boot.py "
               "after a while.")
    FATAL(message)

  global FOUNDATION_LOG_OFFSET_START
  set_log_file(FIRST_BOOT_LOG_FILE_PATH)
  set_log_fatal_callback(log_fatal_callback)
  initialize_ssh_keys(SVM_SSH_KEY_PATH, "/bin/ssh", "/bin/scp")
  try:
    os.makedirs(PHASES_BASE)
  except:
    pass

  # Run this script only if it hasn't reported a failure earlier.
  if os.path.exists(FIRST_BOOT_FAILED_MARKER):
    INFO("First boot has been run before. Not running it again")
    sys.exit()

  # Check if first_boot_cfg.json file exists.
  try:
    with open(FIRST_BOOT_CONFIG_JSON_PATH) as cfg_file:
      first_boot_cfg = json.load(cfg_file)
  except ValueError:
    FATAL("Exception while reading %s" % FIRST_BOOT_CONFIG_JSON_PATH)

  # Unpack JSON (dict) items into a class
  for key, val in first_boot_cfg.items():
    P_LIST.__dict__[key] = val

  hw_config_path = "%s/hardware_config.json" % FIRSTBOOT_SCRIPTS_PATH_BASE
  if os.path.exists(hw_config_path):
    with open(hw_config_path) as hw_config:
      P_LIST.hardware_config = json.load(hw_config)

  # Retrieve last Foundation log offset from firstboot
  if getattr(P_LIST, "foundation_log_offset", None):
    FOUNDATION_LOG_OFFSET_START = P_LIST.foundation_log_offset

  # If not empty, we are using CE version
  if P_LIST.ce_wwns or P_LIST.ce_serials:
    global COMMUNITY_EDITION
    COMMUNITY_EDITION = True

  try:
    P_LIST.hyp_version = [int(x) for x in P_LIST.hyp_version.split('.')]
  except:
    pass

  reboot_required = False
  # Set hypervisor hostname.
  if P_LIST.hypervisor_hostname:
    change_esx_display_name(P_LIST.hypervisor_hostname)
  else:
    change_esx_display_name()
  change_welcome_screen()

  # disable buggy ahci driver only on "6.5.0 GA"
  if P_LIST.hyp_version == [6, 5, 0]:
    stdout, _, __ = run_cmd_new(cmd_array=["vmware", "-vl"])
    if "6.5.0 GA" in stdout and not check_phase("vmw_ahci_disabled"):
      run_cmd(["esxcfg-module", "-d", "vmw_ahci"], fatal=False)
      phase_complete("vmw_ahci_disabled")
      reboot_required = True

  # disable nmlx5_rdma driver on NX platforms
  if "NX" in P_LIST.model_string:
    if not check_phase("nmlx5_rdma_disabled"):
      run_cmd(["esxcfg-module", "-d", "nmlx5_rdma"], fatal=False)
      phase_complete("nmlx5_rdma_disabled")
      reboot_required = True

  is_lenovo = (P_LIST.hardware_config["chassis"]["class"]
                 in ["TSMM", "IMM2"])
  if not check_phase("install_nic_drivers_with_reboot"):
    drivers_list = [
      ("net-i40e-", I40E_NICS, "install_i40e", not is_lenovo,
       True, "Intel Ethernet i40e"),
      ("nmlx5-core", MLX_MT_NICS, "install_mlx5", True,
       False, "Mellanox ConnectX4/5 Ethernet"),
      ("net-ixgbe_", [NIC_10GbE_X550], "install_ixgbe", not is_lenovo,
       True, "Intel Ethernet Ixgbe"),
      ("i40en-", [NIC_25GbE_XXV710], "install_i40en", not is_lenovo,
       True, "Intel Ethernet i40en")
    ]
    reboot_req = install_nic_drivers_with_reboot(drivers_list)
    reboot_required = reboot_required or reboot_req
    phase_complete("install_nic_drivers_with_reboot")

  # Append content to passthru.map
  if not check_phase("passthru_map"):
    with open("/etc/vmware/passthru.map", "a") as p_map:
      with open("%s/passthru.map.snip" % FIRSTBOOT_SCRIPTS_PATH_BASE) as p:
        p_map.write(p.read())
    phase_complete("passthru_map")
    hardware_config = getattr(P_LIST, "hardware_config", None)
    if hardware_config:
      if hardware_config["node"].get("storage_controllers") is not None:
        hbas = hardware_config["node"]["storage_controllers"]
      elif hardware_config["node"].get("storage_controllers_v2") is not None:
        hbas = hardware_config["node"]["storage_controllers_v2"]
      else:
        INFO("All-NVMe setup")
        hbas = []
      for dev in REBOOT_FOR_PASSTHRU:
        for hba in hbas:
          if dev in hba["address"]:
            INFO("Reboot required to make %s available for passthrough"
                 % hba["name"])
            reboot_required = True

  if reboot_required:
    try:
      shutil.copytree("/bootbank/Nutanix", "/altbootbank/Nutanix")
    except OSError:
      INFO("Firstboot scripts already seem to be in altbootbank, so we'll "
           "continue the install.")
    if not P_LIST.is_secureboot:
      preserve_nutanix_module()
      INFO("Rebooting. This may take several minutes")
      run_cmd(["sync"])
      reboot_host()
      sys.exit()
    else:
      INFO("Skipping reboot for Secure boot node")

  if not check_phase("esx_firstboot"):
    script_path = "/esx_host_cfg.sh"
    with open(script_path, "w") as fd:
      for i in range(1,7):
        # Add vmnic1 - vmnic6 to vSwitch0
        fd.write("esxcfg-vswitch --link=vmnic%d vSwitch0 || true\n" % i)
      fd.write("vim-cmd hostsvc/enable_esx_shell\n")
      fd.write("vim-cmd hostsvc/start_esx_shell\n")
      fd.write("vim-cmd hostsvc/enable_ssh\n")
      fd.write("vim-cmd hostsvc/start_ssh\n")
      fd.write("vim-cmd hostsvc/enable_esx_ssh\n")
      fd.write("vim-cmd hostsvc/start_esx_ssh\n")
      fd.write("auto-backup.sh\n")
      fd.write("sync\n")
    run_cmd(["/bin/sh", script_path])
    phase_complete("esx_firstboot")

  # Stop NTP so it doesn't interfere
  run_cmd(["/etc/init.d/ntpd stop >/dev/null 2>&1"], fatal=False)
  api.deny_service_firewall_exception("ntpClient")

  # Set default password to nutanix/4u if this is a gold image based install.
  if P_LIST.hyp_image_path:
    set_default_password()

  # Check to see if this imaging session was invoked using Foundation.
  # If so then setup callbacks and logging
  if P_LIST.monitoring_url_root:
    set_monitoring_url_root(P_LIST.monitoring_url_root)
    set_log_offset(FOUNDATION_LOG_OFFSET_START)
    if P_LIST.monitoring_url_retry_count:
      set_monitoring_url_retry_count(P_LIST.monitoring_url_retry_count)
    if P_LIST.monitoring_url_timeout_secs:
      set_monitoring_url_timeout_secs(P_LIST.monitoring_url_timeout_secs)

    # Nutanix Automation Framework uses Foundation running on non-standard
    # ports and this leads to a lot of dropped packets and delays firstboot
    # by an hour. Open up the port if this is an internal imaging session.
    if getattr(P_LIST, "nutanix_automation_framework_2O17", False):
      open_firewall_port(getattr(P_LIST, "foundation_port", 8000))

  if P_LIST.fc_phx_wf:
    set_fc_imaged_node_uuid(P_LIST.fc_imaged_node_uuid)
    fc_settings = P_LIST.fc_settings
    set_fc_api_key(fc_settings["fc_metadata"]["api_key"])
    set_hyp_type(P_LIST.hyp_type)
    # TODO: Make it configurable later.
    open_firewall_port(9440)

  if not check_phase("firstboot_scripts_started"):
    monitoring_callback("Running firstboot scripts")
    phase_complete("firstboot_scripts_started")

  # Print out first_boot_config.json for troubleshooting.
  # Omit the hw_layout and hardware_config keys to keep the log short.
  fb_copy = copy.deepcopy(first_boot_cfg)
  del fb_copy["hw_layout"]
  fb_copy.pop("hardware_config", None)
  if not check_phase("dump_first_boot_config"):
    INFO("first_boot_config.json = \n%s" % json.dumps(fb_copy, indent=2))
    phase_complete("dump_first_boot_config")
  else:
    DEBUG("first_boot_config.json was dumped, skipping")

  svm_ver = P_LIST.nos_version.split('-')[0]
  try:
    SVM_VERSION[:] = [int(x) for x in svm_ver.split('.')]
  except ValueError:
    pass

  # Disable delayed ack for ESXi 5.5 and later (ENG-19255)
  run_cmd(["/sbin/vsish -e set /net/tcpip/instances/defaultTcpipStack/"
           "sysctl/_net_inet_tcp_delayed_ack 0"], fatal=False)

  # Disable vmk0 interface during install (ENG-11220)
  INFO("Disabling vmk0 network during installation process")
  if not check_phase("disable_network"):
    configure_vmk_interface(disable=True)
    phase_complete("disable_network")

  # Obtain system uuid
  global SYSTEM_UUID
  while not SYSTEM_UUID:
    SYSTEM_UUID = run_cmd(["localcli", "system", "uuid", "get"], retry=True)
  INFO("Obtained %s as uuid of the system" % SYSTEM_UUID)

  # create scratch partition if one is not present
  if (not P_LIST.scratch_present):
    if not check_phase("scratch_created"):
      if P_LIST.hyp_version < [7, 0, 0]:
        # This code is executed neither in 6.x (because ESXi creates a
        # VFAT scratch partition), nor in 7.0 (because 7.0 creates a VMFS-L
        # scratch directory that we can use).
        #
        # Nonetheless I'll leave this code in place because of 'if it ain't
        # broke then don't fix it'.
        #
        # If we had had to create a VFAT scratch area, we would have had
        # to rescan the filesystem so that it would be seen under
        # /vmfs/volumes. That is, we'd run the following command:
        #     'run_cmd_esxcli(["storage filesystem rescan"], fatal=False)'
        INFO("ESX version < 7.0.0, creating scratch partition")
        fs_uuid = create_partition(size_gb=4, fs_type="vfat", strict=False)
        if not fs_uuid:
          FATAL("An error occured while creating the scratch partition")
        with open("/etc/vmware/locker.conf","w") as locker:
          locker.write("/vmfs/volumes/%s 1" % fs_uuid)
      phase_complete("scratch_created")
  else:
    INFO("P_LIST.scratch_present is True, ESX version %s"
         % P_LIST.hyp_version)

  # Now that the VMFS partition has been created some of the larger items
  # should be moved to it to conserve space in bootbank.
  setup_scratch_attrs()
  if not check_phase("conserve_bootbank_space"):
    conserve_bootbank_space()
    phase_complete("conserve_bootbank_space")

  if not check_phase("uninstall_vibs"):
    if P_LIST.hyp_version >= [6, 5, 0]:
      vibs_to_remove = ["lsi-msgpt2", "scsi-mptsas"]
      if "megaraid_sas" not in P_LIST.hardware_config.get("node", {}).get(
         "boot_device", {}).get("controller", ""):
        vibs_to_remove.append("lsi-mr3")
      INFO("Removing vibs: %s as they are not required" % vibs_to_remove)
      for vib in vibs_to_remove:
        run_cmd_esxcli(["software", "vib", "remove",
                        "-n", vib], fatal=False)
    phase_complete("uninstall_vibs")

  dell_vibs = install_dell_vibs()
  if not P_LIST.is_secureboot and not check_phase("install_vibs"):
    # Set vib acceptance level to CommunitySupported
    run_cmd_esxcli(["software", "acceptance", "set",
                    "--level=CommunitySupported"])
    # Dont downgrade i40e and ixgbe vibs for lenovo
    ixgbe_nic_vib = glob.glob("%s/net-ixgbe_*" % P_LIST.VIB_PATH_BASE)
    i40e_nic_vib = glob.glob("%s/net-i40e-*" % P_LIST.VIB_PATH_BASE)
    # Install any other vibs excluding GPU and nic vibs
    # which were taken care of above
    other_vibs = list(set(glob.glob("%s/*" % P_LIST.VIB_PATH_BASE)).difference(
                      set(dell_vibs + i40e_nic_vib + ixgbe_nic_vib)))
    if other_vibs:
      INFO("Installing important vibs")
      install_vibs(other_vibs)
    phase_complete("install_vibs")

  INFO("Configuring ESX host")
  configure_host_common()

  # Apply passthru devices to hypervisor.
  # CE does not need pci passthru.
  if not COMMUNITY_EDITION:
    if not check_phase("passthru_devs"):
      passthru_devs = []
      for dev in P_LIST.passthru_devs:
        if P_LIST.hyp_version >= [6,0,0]:
          dev = "0000:%s" % dev
        passthru_devs.append(dev)

      d_vmd_map = api.map_vmd_devices(passthru_devs)
      # Build vmd_ids and non_vmd_ids lists
      vmd_ids = []
      non_vmd_ids = []
      for key, value in d_vmd_map.items():
        if value:
          vmd_ids.append(key)
        else:
          non_vmd_ids.append(key)

      # It is possible that there is no other device BUT VMD.
      if non_vmd_ids:
        if P_LIST.hyp_version >= [7,0,0]:
          api.set_pci_passthru(non_vmd_ids, applyNow=False)
        else:
          api.set_pci_passthru(non_vmd_ids)
      if vmd_ids:
        vmd_file_path = os.path.join(FIRSTBOOT_SCRIPTS_PATH_BASE,
                                   "iavmd_pt.sh")
        INFO("Storing IAVMD Information for passthru upon boot")
        store_iavmd_passthru(vmd_file_path, vmd_ids)
      phase_complete("passthru_devs")

  # Disable drivers.
  if not COMMUNITY_EDITION:
    if not check_phase("disable_drivers"):
      for driver in filter_boot_drivers(P_LIST, DISABLE_DRIVERS):
        INFO("Disabling driver %s" % driver)
        run_cmd(["/sbin/esxcfg-module -d %s" % driver], fatal=False)
      phase_complete("disable_drivers")

  # Enable sfcbd-watchdog
  if not check_phase("sfcbd_watchdog"):
    if P_LIST.hyp_version >= [6, 5, 0]:
      INFO("Enabling wbem, this will start sfcbd-watchdog")
      run_cmd_esxcli(["system wbem set --enable true"], fatal=False)
    phase_complete("sfcbd_watchdog")

  if P_LIST.vmfs_present or P_LIST.use_vmfs_datastore:
    P_LIST.datastore_path = "/vmfs/volumes/NTNX-local-ds-%s-%s" % \
                               (P_LIST.block_id,P_LIST.node_position)
  else:
    P_LIST.datastore_path = "vmfs/volumes/NTNX-local-ds-nfs-%s-%s" % \
                               (P_LIST.block_id,P_LIST.node_position)

  if not check_phase("create_vmfs_datastore"):
    monitoring_callback("Creating necessary partitions")

  # Set P_LIST.vmfs_present again if no datastore found.
  if P_LIST.use_vmfs_datastore:
    if P_LIST.vmfs_present and not api.local_datastore:
      INFO("VMFS partition exists, but ESX didn't mount it."
          " It might be corrupted, deleting the last partition and re-creating"
          " datastore from it.")
      delete_last_partition()
      P_LIST.vmfs_present = False

  # Create or rename local VMFS datastore.
  if P_LIST.use_vmfs_datastore:
    if not P_LIST.vmfs_present:
      if not check_phase("create_vmfs_datastore"):
        P_LIST.vmfs_uuid = create_vmfs_partition(
                                 os.path.basename(P_LIST.datastore_path))
        phase_complete("create_vmfs_datastore")
    else:
      # Rename local VMFS datastore from the default name of 'datastore1'
      if api.local_datastore:
        if not check_phase("rename_vmfs_datastore"):
          if len(api.host_obj.datastore) > 1:
            FATAL("More than one datastore exists on the host:\n%s\n"
              "If you've manually installed ESX, ensure that the host only has"
              "a single  datastore backed by the host boot disk before "
              "installing NOS, usually by not adding the node to vcenter." %
              ",".join(api.host_obj.datastore))
          api.rename_datastore(api.local_datastore,
                               os.path.basename(P_LIST.datastore_path))
          phase_complete("rename_vmfs_datastore")
        P_LIST.vmfs_uuid = api.local_datastore.info.vmfs.uuid

  # Deploy ssh keys.
  if not check_phase("deploy_ssh_keys"):
    run_cmd(["tar xvzf %s/ssh.tgz -C /" % FIRSTBOOT_SCRIPTS_PATH_BASE])
    phase_complete("deploy_ssh_keys")

  # Set "useDns no" in sshd config.
  if not check_phase("modify_sshd_config"):
    modify_sshd_config()
    phase_complete("modify_sshd_config")

  # Insert nutanix.tgz module in altbootbank before reboot.
  if not check_phase("update_altbootbank"):
    preserve_nutanix_module()
    phase_complete("update_altbootbank")

  if not check_phase("first_boot"):
    monitoring_callback("Rebooting host, this may take several minutes")
    INFO("Rebooting system. This may take several minutes")
    # Checkpoint first_boot_config.json
    P_LIST.foundation_log_offset = get_log_offset()
    with open(FIRST_BOOT_CONFIG_JSON_PATH, "w") as cfg_file:
      json.dump(P_LIST.__dict__, cfg_file)
    phase_complete("first_boot")

    try:
      shutil.copytree("/bootbank/Nutanix", "/altbootbank/Nutanix")
    except OSError:
      INFO("Firstboot scripts already seem to be in altbootbank, so we'll "
           "continue the install.")

    # TODO: maybe save this reboot by configure passthru early?

    api.disconnect()
    reboot_host()
    sys.exit()

  # Callback to Foundation to notify of success
  monitoring_callback("First reboot complete", "ESXi firstboot successful.")

  monitoring_callback("Creating a new CVM")
  # Extract svmrescue.iso from raw block device.
  if (P_LIST.use_vmdk_svm_disk):
    if not check_phase("extract_svmfactory"):
      extract_svmfactory_iso()
      phase_complete("extract_svmfactory")

  # Deploy SVM
  if (P_LIST.use_vmdk_svm_disk):
    if not check_phase("deploy_svm_vmdk"):
      deploy_svm_on_vmdk()
      phase_complete("deploy_svm_vmdk")
  else:
    customize_svm_from_template()
    if COMMUNITY_EDITION:
      create_svm_vmx_and_attach_rdm_disks_ce()

  # Stage pynfs local.sh content and start pynfs if this
  # node is a node which uses pynfs.
  if not check_phase("pynfs_datastore"):
    INFO("Configuring pynfs datastore")
    if not P_LIST.use_vmfs_datastore:
      pynfs_source = os.path.join(FIRSTBOOT_SCRIPTS_PATH_BASE, "pynfs.tar.gz")
      pynfs_dst = "/bootbank/pynfs.tar.gz"
      run_cmd(["cp", pynfs_source, pynfs_dst])
    run_cmd(["/bin/sh", NFS_CONFIG_SCRIPT_PATH, SYSTEM_UUID,
            os.path.basename(P_LIST.datastore_path)],
            retry=True, timeout=(10 * MINUTE))
    phase_complete("pynfs_datastore")

  INFO("Registering the SVM")
  api.svm = api.retry_function_until_success(api.register_vm,
                        (os.path.basename(P_LIST.datastore_path),
                         "%s/%s.vmx" % (SVM_NAME, SVM_NAME)))
  configure_svm_resources()

  # Overwrite rc file content
  if not check_phase("rc_local_update"):
    if os.path.exists("/etc/rc.local.d/local.sh"):
      # ESXi versions >= 5.1.0
      rc_file = "/etc/rc.local.d/local.sh"
    else:
      # ESXi versions < 5.1.0
      rc_file = "/etc/rc.local"

    with open(rc_file,"w") as rc:
      try:
        with open("/etc/rc.local.d/rc_nutanix.sh") as rc_n:
          rc.write(rc_n.read())
      except IOError as e:
        WARNING("Ignoring content from rc_nutanix.sh: %s" % str(e))
      # Append pynfs content to rc file.
      with open("/tmp/pynfs_start.sh") as pynfs:
        rc.write(pynfs.read())
      # Append CVM startup content to rc file
      with open(FIRSTBOOT_SCRIPTS_PATH_BASE + "/auto_start.snip") as auto_start:
        rc.write(auto_start.read())

      vmd_file_path = os.path.join(FIRSTBOOT_SCRIPTS_PATH_BASE,
                                   "iavmd_pt.sh")
      # Append VMD enablement content to rc file
      if os.path.exists(vmd_file_path):
        with open(vmd_file_path) as vmd_code:
          rc.write(vmd_code.read())

      os.fsync(rc.fileno())
    os.chmod(rc_file, 0o755)

    phase_complete("rc_local_update")

  if not P_LIST.is_secureboot:
    # Remove nutanix.tgz from boot.cfg
    update_boot_cfg("nutanix.tgz", remove=True, bootbank="bootbank")
    update_boot_cfg("nutanix.tgz", remove=True, bootbank="altbootbank")

  power_state = api.get_vm_power_state(api.svm)
  if (power_state != "poweredOn"):
    api.svm.PowerOn()
    monitor_svm_power_state("poweredOn", timeout=(1 * MINUTE))

  # Power on the SVM and wait for /tmp/svm_boot_succeeded to be created
  # Check that the VM is powered on (in NX-2k the SVM will already be on)
  # if not on then it power on.
  # If fails to find marker file and able to ssh CVM, then copy
  # available cvm boot logs to hypervisor.
  for attempt in range(0, MAX_ATTEMPTS):
    out, err, ret = run_cmd_on_svm(cmd="ls %s" % "/tmp/svm_boot_succeeded",
                                   attempts=3, fatal=False, quiet=True)
    if not ret:
      # succeded
      break
    message = "Waiting until CVM boots up"
    prefix = "[%s/%s] " % (attempt + 1, MAX_ATTEMPTS)
    INFO(prefix + message)
  else:
    _, _, ret = run_cmd_on_svm(cmd="ls", attempts=3, fatal=False)
    if not ret:
      copy_to = os.path.join(FIRSTBOOT_SCRIPTS_PATH_BASE, "cvm_logs")
      copy_cvm_logs_to_hypervisor(copy_to)
      FATAL("CVM has started but is taking longer than usual to finish "
            "bootstrapping. Available logs are copied to %s on the "
            "hypervisor." % copy_to)
    else:
      FATAL("Cvm has failed to boot up. Please open the cvm console manually "
            "and check for any cvm boot errors.")
  monitoring_callback("CVM booted up successfully")

  if not check_phase("final_svm_conf"):
    # Create one node clusters if set
    one_node_install_success_path = ("%s/%s" % (FIRSTBOOT_SCRIPTS_PATH_BASE,
                                                ONE_NODE_INSTALL_SUCCESS))
    if os.path.exists(one_node_install_success_path):
      cmd = """
           ALL_IPS=\`hostname -I\`;
           CVM_IP=\`for i in \$ALL_IPS; do echo \$i | grep -v 192.168.5 |
           grep -v 127.0.0.1; done\`;
           if [ "\$CVM_IP" == "" ]; then echo -n "Could not detect CVM IP.";
           exit 1; fi; source /etc/profile.d/nutanix_env.sh;
           echo Y | cluster -s \$CVM_IP --redundancy_factor=2 create
          """
      out, _, _ = run_cmd_on_svm(cmd, timeout=(10 * 60), fatal=False)
      if "The state of the cluster: start" in out:
        INFO("Cluster created")
      else:
        ERROR("Cluster could not be created. Please do so manually via the "
             "command line. See the online documentation for further details.")

    # Rename the SVM to normal display name.
    change_svm_display_name()
    # Update Autostart policy for SVM
    api.set_vm_autostart_policy(api.svm, 1, startDelay=30, startAction="PowerOn")
    phase_complete("final_svm_conf")

  # Assign the hypervisor MGMT interface a VLAN id if one is present.
  if getattr(P_LIST, "cvm_vlan_id", None):
    api.assign_portgroup_vlanId(PG_MGT_NET, P_LIST.cvm_vlan_id)
    api.assign_portgroup_vlanId(PG_VM_NET, P_LIST.cvm_vlan_id)

  INFO("Configuring vmk0 interface")
  configure_vmk_interface()

  change_welcome_screen(clear=True)
  # Create a 'first boot success' marker.
  run_cmd(["touch", FIRST_BOOT_SUCCESS_MARKER])

  # Run auto-backup.sh
  INFO("Running auto-backup.sh")
  run_cmd(["sh", "/sbin/auto-backup.sh"])

  run_cmd(["rm -rf %s" % P_LIST.scratch_path], fatal=False)
  try:
    shutil.copyfile(FIRST_BOOT_LOG_FILE_PATH, '/bootbank/first_boot.log')
    shutil.copyfile(INSTALLER_LOG_FILE_PATH, '/bootbank/installer.log')
    if getattr(P_LIST, "delete_fb_on_success", True):
      run_cmd(["rm -rf /bootbank/Nutanix /altbootbank/Nutanix"])
  except:
    pass

  # nutanix.tgz has no purpose at this point. Removing it to make enabling
  # secure boot easier.
  try:
    os.remove("/tardisks/nutanix.tgz")
  except OSError:
    pass

  monitoring_callback("Last reboot complete")
  api.disconnect()

if __name__ == "__main__":
  try:
    main()
  except Exception:
    FATAL("Fatal exception encountered:\n%s" % format_exc())
