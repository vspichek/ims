# Integrity Measurement Service (IMS)
This document is work in progress and is updated as needed.

## Introduction
Purpose is verification of internal state of an embedded system. Internal state includes, among others, following elements: firmware, boot loader, OS core and system configuration. Unsuccessful verification indicates a possible compromise, and that system cannot be trusted. Exact response to unsuccessful verification is responsibility of users of this service.

Verification consist of two phases: measurement collection (in form of a log) and comparison of the collected measurements against known good values. This document describes the service that does collection of measurements.

## Hardware vs software
Extensive support exists for hardware assisted platform integrity measurement collection. Notable example is TPM (and Intel TXT) backed Trusted boot. In case of Linux it’s further supported by IMA subsystem in Linux kernel. Unfortunately, Trusted boot doesn’t support Linux/UEFI, additionally TPM (or other hardware) isn’t always present. This document describes pure software approach to IMS.

## Measurements
Element measurement is a piece of data which allows to determine whether the element has been tampered. For performance reasons each individual measurements contain not entire element of system state (OS kernel, configuration file, etc), but a cryptographically strong digest of the element. With trusted digest algorithms it’s considered highly improbable to encounter two different elements having the same digest.

This IMS supports, among others, SHA256. Support for different algorithms can be added via plugins and/or configuration.

## Measurement providers
IMS code doing measurement collection interacts with external (to IMS) systems in various ways. In most cases these systems need to be configured to provide measurements, and, typically, permission needs to be granted to IMS to access those systems.

Combination of external system, its configuration and corresponding IMS code is called **measurement provider**.
Each provider is assigned an UUID.

This IMS initially supports following providers (described below):
* UEFI firmware and bootloader measurement provider
* OS core measurement provider
* Linux IMA measurement provider
* Filesystem measurement provider

Support for different providers can be added via plugins.

## Measurement log (ML)
Set of measurements signed by IMS private key.

Initial version of ML has following format:

Entry | Type | Required? | Comment
--- |:---:| --- | ---
IMS version (implies version of ML format) | String | Mandatory
Format descriptor (FD) | Compound | Mandatory | Specifies format, type and precision of various data elements  of the ML
Configuration | per FD | Mandatory | Runtime configuration of this instance of IMS. Includes parameters of all providers
System ID | per FD | Optional | Identifies the system which measurements belong to
Time(system clock) | per FD | Optional | Time when ML generated
System uptime | per FD | Mandatory | Time elapsed since boot of the system
List of measurements | See below | Mandatory

##### Configuration descriptor
* System ID data type
* Data type and precision of system clock data elements
* Data type and precision of system uptime
* Provider enumeration: map `provider_UUID → provider_ordinal`
* Digest type mapping: map `provider_UUID → digest_format_and_algo_UUID`
* Element ID type mapping: map `provider_UUID → element_id_format_UUID`

See **JSON rendering of an ML** below for a possible representation of Configuration descriptor

##### List of measurements
As it’s not always possible establish total order of events in a system, this is actually not a list but a DAG. Where available causality/ordering is exposed.

Each measurement has following format

Entry | Type | Required? | Comment/Example
--- |:---:|:---:| ---
ID | Ordinal | Mandatory |
Provider | Ordinal | Mandatory | example: filesystem provider (FS)
Previous ID | List of Ordinals | Mandatory | The list can be empty
System uptime | per FD | Optional | Time the measurement was taken
Element ID | per FD (provider specific) | Optional | File name in case of FS provider
Digest | per FD (Provider specific) | Mandatory | Hash metadata + hash of file content in case of FS provider

Once collected, measurement log is signed by IMS private key.
Private key is stored in Linux kernel keyring and is inaccessible to the process, as described here: [keyctl operations for asymmetric keys](https://lwn.net/Articles/692514/).
Expectation is that this kernel feature will eventually be backed by SGX(where available).

Serialization format: **TBD**

## UEFI firmware and bootloader measurement provider
This provider performs `Time-Of-Use` measurements of UEFI firmware and bootloader.

As TPM is unavailable, a driver needs to be added to platform firmware.
The driver performs measurements and stores them in a `Write-once` EFI variable.
The driver is modeled(or patched) on Intel reference [1](https://github.com/tianocore/edk2/tree/master/SecurityPkg/Library/DxeImageVerificationLib), [2](https://github.com/tianocore/edk2/tree/master/SecurityPkg/Library/DxeTpmMeasureBootLib), etc.
Firmware then needs to be modified to to include the driver. One example of how it can be done is [here](http://www.win-raid.com/t871f16-Guide-How-to-get-full-NVMe-support-for-Intel-Chipset-systems-from-Series-up.html). It is believed only DXE phase of boot would be affected.

IMS side of this provider collects measurement result from an EFI variable.

###### Parameters
* name of EFI variable

###### Configuration
* Modified UEFI firmware needs to be installed
* EFI variables in `/sys/firmware/efi/efivars` need to be readable (may require an entry in IMS SELinux policy)

###### UUID: f17e2ff5-2209-47b8-a3c9-d1c7679597d7

## OS core measurement provider
This provider performs `Time-Of-Use` measurements of Linux kernel, initrd and GRUB configuration.

Data for this provider is collected by a bootloader. Standard GRUB doesn't support measurements, nor TPM.
[TrustedGrub](http://trousers.sourceforge.net/grub.html) doesn't support UEFI. This provider requires a modified GRUB bootloader.
Measurement and TPM support was recently added to [coreos/grub](https://github.com/coreos/grub) by [mjg59](https://github.com/mjg59/grub).
As TPM is unavailable, a patch to **coreos/grub** is needed so that the bootloader stores measurements not in TPM, but in a `Write-once` EFI variable.

IMS side of this provider collects measurement result from an EFI variable.

###### Parameters
* name of EFI variable

###### Configuration
* Modified GRUB2 needs to be installed
* EFI variables in `/sys/firmware/efi/efivars` need to be readable (may require an entry in IMS SELinux policy)

###### UUID: TBD

## Linux IMA measurement provider
This provider performs `Time-Of-Use` measurements on individual files.
Leverages existing subsystem of Linux kernel.

###### Parameters
* location of measurement file, i.e. `/sys/kernel/security/ima/binary_runtime_measurements`

###### Configuration
* Kernel needs to be booted with `ima=on`, `ima_tcb`, etc options
* Filesystems need to be mounted with `i_version` option
* `/sys/kernel/security/ima/binary_runtime_measurements` needs to be readable (may require an entry in IMS SELinux policy)
* IMA policy needs to be loaded to capture desired part of OS/App configuration
* SELinux labels need to be applied to corresponding files

###### UUID: 9732a796-db68-4822-b79d-3bfbef3e7470

## Filesystem measurement provider
This provider performs measurements on individual files on mounted filesystems.
Similarly to Linux IMA provider, it measures file metadata along with data.
To be used as primary testing tool for the rest of IMS, and as a fallback provider in deployments where Linux IMA is unavailable or undesirable.

It’s understood that with this provider's `Time-Of-Check` is different from `Time-Of-Use`

###### Parameters
* List of filesystem path prefixes to measure, and
* List of filesystem path prefixes to skip

###### Configuration
* Read permission is affected by acls, setuid, process capabilies, SELinux/AppArmor policies, etc
* Filesystem namespaces (chroot/containers) also affect outcome

###### UUID: TBD

## JSON rendering of an ML
```javascript
{ "ims_ver": "0.0.1",
  "format_descriptor": {
    "configuration": "string",
    "system_id": "string",
    "time": "f11391c7-130a-45e1-95ea-f58971a24e94", // unix_time millisecond
    "uptime": "6f06bf63-6a78-44e2-bd27-5f10e949ee18", //seconds since boot
    "provider_enum": {
      "f17e2ff5-2209-47b8-a3c9-d1c7679597d7": 1, // UEFI firmware
      "9732a796-db68-4822-b79d-3bfbef3e7470": 2  // Linux IMA
    },
    "provider_digest": {
      "f17e2ff5-2209-47b8-a3c9-d1c7679597d7": "a8fc53ce-2a9c-4c8e-9fc6-7bfa2c252cfd", // Firmware hash
      "9732a796-db68-4822-b79d-3bfbef3e7470": "de611c93-d4a7-40d6-98da-929f8e30c859"  // File metadata hash, data hash
    },
    "provider_element": {
      "9732a796-db68-4822-b79d-3bfbef3e7470": "1ffb341f-a5aa-4556-a6be-bb37e9494e6e" // string with file name
    }
  },
  "configuration": "#this is a comment\nenabled_providers=uefi_firmware,linux_ima\nlinux_ima.source=/sys/kernel/security/ima/binary_runtime_measurements",
  "system_id": "samsung_smart_frige_sn2389457a",
  "time": 1700000000000,
  "uptime": 60,
  "ml": [{
    "id": 1,
    "provider": 1,
    "previous": [],
    "digest": "247ac80fb10a7e5a9d0c14074188c1131aaa7b020ad4590cdfd8a5131dd2436a"
  }, {
    "id": 2,
    "provider": 2,
    "previous": [1],
    "uptime": 59,
    "element": "/usr/share/images/logo.png"
    "digest": "60d4aa2c3feba4416ebfecbedb61d97777443e5d,afaf91282a294032f128da6dd154dddb07eb1bbfab3ceca077b833a924bee1f1"
  }]
}
```

Well known UUID | Description
--- | ---
f17e2ff5-2209-47b8-a3c9-d1c7679597d7 | UEFI firmware provider
9732a796-db68-4822-b79d-3bfbef3e7470 | Linux IMA provider
a8fc53ce-2a9c-4c8e-9fc6-7bfa2c252cfd | sha256 hash algorithm
de611c93-d4a7-40d6-98da-929f8e30c859 | (sha1,sha256) tuple: sha1 over file metadata, sha256 over file data
1ffb341f-a5aa-4556-a6be-bb37e9494e6e | String
f11391c7-130a-45e1-95ea-f58971a24e94 | Number of milliseconds since 1970
6f06bf63-6a78-44e2-bd27-5f10e949ee18 | Number of seconds since boot

## Open questions
* `Write-once` EFI variables availability/compatibility
* Availability of generic procedure of UEFI driver addition
* Weigh costs/benefits of multiprocess IMS (whether to allow provider plugins to spawn processes)
* etc