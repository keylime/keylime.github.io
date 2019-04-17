---
layout: blog
title:  "Overview of Keylimes Runtime Integrity Management"
author: "Luke Hinds"
date:   2019-04-02
---

A feature of Keylime is runtime integrity monitoring, using the integrity management architecture (IMA).

## Intro to IMA

IMA was introduced to the Linux Kernel on the 20th May 2005 for the Kernel release 2.6.30 as part of the overall
Linux Integrity Subsystem. The design was based upon the work of the open standard for trusted compute by the Trusted Computing Group (TCG).

IMA (also known as the kernel integrity subsystem) provides a means of detecting whether files have been accidentally or maliciously altered or executed both remotely or locally.

The following modules provide the integrity functions:

* Collect – measure a file before it is accessed.
* Store – add the measurement to a kernel resident list and, if a
hardware Trusted Platform Module (TPM) is present, extend the IMA
PCR
* Attest – if present, use the TPM to sign the IMA PCR value, to
allow a remote validation of the measurement list.
* Appraise – enforce local validation of a measurement against a
“good” value stored in an extended attribute of the file.
* Protect – protect a file's security extended attributes
(including appraisal hash) against off-line attack.
* Audit – audit the file hashes.

Keylime makes use of the attest function "IMA-measurement"

## IMA-measurement

IMA maintains a runtime measurement list and, if a hardware Trusted Platform Module (TPM) is present, the list is anchored within the Trusted Platform Modules (TPM) Platform Configuration Registers (`PCR`). The benefit of anchoring the aggregate integrity value in the TPM is that the measurement list cannot be compromised by any software attack, without being detectable. Hence, on a trusted boot system, IMA-measurement can be used to attest to the system's runtime integrity remotely (or locally).

A majority of Linux distributions now have IMA measurement enabled by default. For this article we will use Fedora 29, but the feature is available in many earlier versions of the RHEL and Debian family, alongside Gentoo, Arch Linux and OpenSUSE.

Quite often, all that is required is an `ima-policy`. This is then placed into `/etc/ima/ima-policy`. In keylime, for demo purposes we provide the following `ima-policy`

```
# PROC_SUPER_MAGIC
dont_measure fsmagic=0x9fa0
# SYSFS_MAGIC
dont_measure fsmagic=0x62656572
# DEBUGFS_MAGIC
dont_measure fsmagic=0x64626720
# TMPFS_MAGIC
dont_measure fsmagic=0x01021994
# RAMFS_MAGIC
dont_measure fsmagic=0x858458f6
# SECURITYFS_MAGIC
dont_measure fsmagic=0x73636673
# MEASUREMENTS
measure func=BPRM_CHECK
measure func=FILE_MMAP mask=MAY_EXEC
measure func=MODULE_CHECK uid=0
```

This default policy measures all executables in `bprm_check`, all files mmapped executable in `file_mmap`, and all files
open for read by `root` in `do_filp_open`.

It is of course possible to create your own IMA policy, along with LSM specific definitions for `SELinux` or `Smack`.

One example using SELinux, would be to what IMA watch all files in `/etc/`

`measure func=FILE_CHECK mask=MAY_READ obj_type=etc_t`

Once your `ima-policy` is in place, reboot your machine (or have it present in your image for first boot)

You can then verify its function by looking at IMA's measurement file (Event-log) located on `securityfs`:

`/sys/kernel/security/ima/ascii_runtime_measurements`

```
# head -5 /sys/kernel/security/ima/ascii_runtime_measurements
PCR                                  template-hash filedata-hash                                  filename-hint
10 3c93cea361cd6892bc8b9e3458e22ce60ef2e632 ima-ng sha1:ac7dd11bf0e3bec9a7eb2c01e495072962fb9dfa boot_aggregate
10 3d1452eb1fcbe51ad137f3fc21d3cf4a7c2e625b ima-ng sha1:a212d835ca43d7deedd4ee806898e77eab53dafa /usr/lib/systemd/systemd
10 e213099a2bf6d88333446c5da617e327696f9eb4 ima-ng sha1:6da34b1b7d2ca0d5ca19e68119c262556a15171d /usr/lib64/ld-2.28.so
10 7efd8e2a3da367f2de74b26b84f20b37c692b9f9 ima-ng sha1:af78ea0b455f654e9237e2086971f367b6bebc5f /usr/lib/systemd/libsystemd-shared-239.so
10 784fbf69b54c99d4ae82c0be5fca365a8272414e ima-ng sha1:b0c601bf82d32ff9afa34bccbb7e8f052c48d64e /etc/ld.so.cache
```

> Note: The above list is in sha1, but up to sha512 can be used.

Looking at the above list with the tool `tpm2_pcrlist`, we can see a row marked `PCR` with a value of `10`

A PCR is a 'Platform Configuration Register'.

If we then look at `PCR` `10` in our TPM, we can see a hash value (two in fact, one for `sha1` the other for `sha256`:

```
# tpm2_pcrlist | grep '10:'
  10: 0x0F02EF35C7B90B8F15673B76A1DCF32D3837B986
  10: 0xF8591262DE028F66CAA3EC182091061E7A437A328253D97E9807260937E7D055
```

## Platform Configuration Registers

Let's explore `PCRs` a bit more.

A Platform Configuration Register is a value that can only be set by the TPM and is a recorded measurement of a system object (by object we could mean file, firmware, bootloader, kernel, etc).

One of the main functions of a PCR is the `extend` operation.

`tpm2_pcrextend 10:sha1=f1d2d2f924e986ac86fdf7b36c94bcdf32beec16`

> The above command asks the TPM to extend the hash `f1d2d2f924e986ac86fdf7b36c94bcdf32beec16` into `PCR 4`

Each time an `extend` is made the following mathematical operation occurs:

`PCR New Value = Digest of (PCR old value || data to extend)`

Here is a simple example in python code:

```
import hashlib

hash_one = hashlib.sha1(b'hello')
hash_two = hashlib.sha1(b'world')
hex_dig_one = hash_one.hexdigest()
hex_dig_two = hash_two.hexdigest()

# concatenate hashes
extend_hash = hex_dig_one.encode('utf-8') + hex_dig_two.encode('utf-8')

# recompute concatenated hash
extend = hashlib.sha1(extend_hash)
extend_dig = extend.hexdigest()

print("hello hash: ", hex_dig_one)
print("world hash: ", hex_dig_two)
print("extended hash: ", extend_dig)
```

```
python ext.py                                                                                                                                                                                                                                              ✔  535  14:17:29  
hello hash:  aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
world hash:  7c211433f02071597741e6ff5a8ea34789abbf43
extended hash:  39955b37b910e57748368b0922fd44fbff72bda5
```

This is a one way hash. A one-way hash function is designed in such a way that it is hard to reverse the process, that is, to find a string that hashes to a given value (hence the name one-way.) A hash function also makes it hard to find two strings that would produce the same hash value.

## Core Root of Trust Measurement (CRTM)

When a platform is rebooted / powered on, all PCRs are set to zero.

On a UEFI system, a series of early boot sequences occur, with one of them being the Core Root of Trust Measurement (CRTM). This is the first measurement written to `PCR: 0`. The CRTM then measures BIOS & boot loader, extending those into `PCR: 0`

## Linux IMA

Early in the OS boot process, Linux IMA (also measured as part of the Kernel in `PCR: 0`) measures (hashes) a policy-based list (`/etc/ima/ima-policy`) of files into `PCR: 10`. The final aggregate hash in `PCR: 10` is then the record of the state of the measured files/directories at time of boot. This record can then be made public (Event Log) and attested using the public key of the TPM.

This attestation mentioned above is achieved using a TPM Quote, where a number of PCRS are hashed, and that hash is signed by a TPM key, accessable only to the TPM.

> Note: Various other PCRs are used for hashing objects such as grubs command line options. 24 PCRs are available in total.

## Wrap up

So with the CRTM based boot process measured and IMA measured files (including runtime access of said files), we have a full attested boot state and runtime integrity environment. Keylime Agent can measure both of these processes and perform a remote attestation using the Keylime Verifier.

For the second section of this blog post, we will go into setting up Keylime to perform a runtime measuring environment, which will sense a non whitelisted script being run by root, which results in the remote Keylime Verifier revoking the agent.

## KeyLime IMA

We are going to create two files. A `whitelist.txt` and an `excludes.txt`

## whitelist

The whitelist is a list of what we consider to be golden values (or in fact measurements). We will use the initramfs to create our whitelist using the `create_whitelist.sh` shell script available in th keylime repository [here](https://github.com/keylime/keylime/blob/master/keylime/create_whitelist.sh) or `keylime/keylime/create_whitelist.sh`

We will then remotely send this whitelist to the keylime verifier, which will then proceed to request quotes from the Keylime Agent. Next we will run a non-whitelisted script as root, and see how this results in the verifier revoking the monitored agent. For this we use Fedora 29, but other versions /dists can be used ( check with the community on [gitter.im](https://gitter.im/keylime-project/community) for more info.)

Firstly install Keylime using the installer or the ansible playbook (if you need a simulator). Make sure you can communicate with TPM:

```
# tpm2_getrandom 8
0x0A 0xBB 0xEB 0xB7 0x82 0x40 0xC1 0x08
```

On any machine (this could be an unplugged machine for extra security) run the `create_whitelist.sh` script as follows:

```
# ./create_whitelist.sh ~/whitelist.txt sha1sum
Writing whitelist to /root/whitelist.txt with sha1sum...
Creating whitelist for init ram disk
extracting /boot/initramfs-4.18.16-300.fc29.x86_64.img
extracting /boot/initramfs-5.0.4-200.fc29.x86_64.img
```

## Enable IMA policy

Create the file `/etc/ima/ima-policy` (you may need to create the `/etc/ima/` directory first) and enter the following:

```
dont_measure fsmagic=0x9fa0
# SYSFS_MAGIC
dont_measure fsmagic=0x62656572
# DEBUGFS_MAGIC
dont_measure fsmagic=0x64626720
# TMPFS_MAGIC
dont_measure fsmagic=0x01021994
# RAMFS_MAGIC
dont_measure fsmagic=0x858458f6
# SECURITYFS_MAGIC
dont_measure fsmagic=0x73636673
# MEASUREMENTS
measure func=BPRM_CHECK
measure func=FILE_MMAP mask=MAY_EXEC
measure func=MODULE_CHECK uid=0
```

> Note, a copy of the above is also available in `keylime/demo/``

Reboot the machine to get IMA to populate `/sys/kernel/security/ima/ascii_runtime_measurements`.

When the machine is back up, check that `ascii_runtime_measurements` is populated:

```
PCR                                  template-hash filedata-hash                                  filename-hint
10 3c93cea361cd6892bc8b9e3458e22ce60ef2e632 ima-ng sha1:ac7dd11bf0e3bec9a7eb2c01e495072962fb9dfa boot_aggregate
10 3d1452eb1fcbe51ad137f3fc21d3cf4a7c2e625b ima-ng sha1:a212d835ca43d7deedd4ee806898e77eab53dafa /usr/lib/systemd/systemd
10 e213099a2bf6d88333446c5da617e327696f9eb4 ima-ng sha1:6da34b1b7d2ca0d5ca19e68119c262556a15171d /usr/lib64/ld-2.28.so
10 7efd8e2a3da367f2de74b26b84f20b37c692b9f9 ima-ng sha1:af78ea0b455f654e9237e2086971f367b6bebc5f /usr/lib/systemd/libsystemd-shared-239.so
10 784fbf69b54c99d4ae82c0be5fca365a8272414e ima-ng sha1:b0c601bf82d32ff9afa34bccbb7e8f052c48d64e /etc/ld.so.cache
```

We now start the `keylime_veriifier`, `keylime_register`, and the '`keylime_agent`:

> Note, if you're using an emulator change to `require_ek_cert = False` in `/etc/keylime.conf` first.

> Note 2, you will also need the `ima_stub_service` if using an emulator, as standard IMA expects a hardware TPM present at boot time.
> Run `ima_stub_service/./installer.sh` and then enable / start the service `systemctl enable tpm_emulator` `systemctl start tpm_emulator`

```
# keylime_verifier
Using config file /etc/keylime.conf
1554292794.84 - keylime.cloudverifier - INFO - Starting Cloud Verifier (tornado) on port 8881, use <Ctrl-C> to stop
1554292794.84 - keylime.cloudverifier_common - INFO - Setting up TLS...
1554292794.84 - keylime.cloudverifier_common - INFO - Generating a new CA in /var/lib/keylime/cv_ca and a client certificate for connecting
1554292794.84 - keylime.cloudverifier_common - INFO - use keylime_ca -d /var/lib/keylime/cv_ca to manage this CA
1554292794.84 - keylime.cloudverifier_common - WARNING - CAUTION: using default password for CA, please set private_key_pw to a strong password
1554292794.92 - keylime.ca_impl_openssl - WARNING - CRL creation with openssl is not supported
1554292794.92 - keylime.ca-util - INFO - CA certificate created successfully in /var/lib/keylime/cv_ca
1554292794.96 - keylime.ca-util - INFO - Created certificate for name localhost.localdomain successfully in /var/lib/keylime/cv_ca
1554292795.05 - keylime.ca-util - INFO - Created certificate for name client successfully in /var/lib/keylime/cv_ca
1554292795.05 - keylime.cloudverifier - INFO - Starting service for revocation notifications on port 8992
```

```
# keylime_registrar
Using config file /etc/keylime.conf
1554292843.95 - keylime.cloudverifier_common - INFO - Setting up TLS...
1554292843.95 - keylime.registrar-common - INFO - Starting Cloud Registrar Server on ports 8890 and 8891 (TLS) use <Ctrl-C> to stop
```

```
# keylime_agent
Using config file /etc/keylime.conf
1554292887.77 - keylime.secure_mount - DEBUG - secure storage location /var/lib/keylime/secure not mounted
1554292887.77 - keylime.secure_mount - INFO - mounting secure storage location /var/lib/keylime/secure on tmpfs
1554292887.85 - keylime.tpm - WARNING - INSECURE: Keylime is using a software TPM emulator rather than a real hardware TPM.
1554292887.85 - keylime.tpm - WARNING - INSECURE: The security of Keylime is NOT linked to a hardware root of trust.
1554292887.85 - keylime.tpm - WARNING - INSECURE: Only use Keylime in this mode for testing or debugging purposes.
1554292887.85 - keylime.tpm2 - INFO - Taking ownership with config provided TPM owner password: keylime
1554292888.03 - keylime.tpm2 - INFO - TPM Owner password confirmed: keylime
1554292888.96 - keylime.tpm2 - WARNING - No EK certificate found in TPM NVRAM
1554292888.96 - keylime.tpm2 - DEBUG - Creating a new AIK identity
1554292891.4 - keylime.cloudagent - INFO - agent UUID: D432FBB3-D2F1-4A97-9EF7-75BD81C00000
1554292891.46 - keylime.registrar_client - INFO - agent registration requested for D432FBB3-D2F1-4A97-9EF7-75BD81C00000
1554292891.46 - keylime.secure_mount - DEBUG - secure storage location /var/lib/keylime/secure already mounted on tmpfs
1554292892.52 - keylime.tpm2 - INFO - AIK activated.
1554292892.57 - keylime.registrar_client - INFO - Registration activated for agent D432FBB3-D2F1-4A97-9EF7-75BD81C00000.
1554292892.58 - keylime.secure_mount - DEBUG - secure storage location /var/lib/keylime/secure already mounted on tmpfs
1554292892.58 - keylime.cloudagent - DEBUG - key not found, generating a new one
1554292892.9 - keylime.tpm2 - DEBUG - No stored U in TPM NVRAM
1554292892.9 - keylime.cloudagent - INFO - Starting Cloud agent on port 9002 use <Ctrl-C> to stop
1554292892.9 - keylime.revocation_notifier - INFO - Waiting for revocation messages on 0mq 127.0.0.1:8992
```

Finally let's provision our agent with the whitelist we created earlier, but before that, we will create a `excludes.txt`

`# touch excludes.txt`

> Note: `excludes.txt` is empty for now, we can populate this later.


```
# keylime_tenant -v 127.0.0.1 -t 127.0.0.1 -f /root/excludes.txt --uuid D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --whitelist /root/whitelist.txt --exclude /root/exclude.txt -c update
Using config file /etc/keylime.conf
1554293118.67 - keylime.tenant - WARNING - CAUTION: using default password for private key, please set private_key_pw to a strong password
1554293118.67 - keylime.tenant - INFO - Setting up client TLS in /var/lib/keylime/cv_ca
1554293118.68 - keylime.tenant - INFO - TPM PCR Mask from policy is 0x408000
1554293118.68 - keylime.tenant - INFO - vTPM PCR Mask from policy is 0x808000
1554293118.69 - keylime.ima - DEBUG - Loaded whitelist from /root/whitelist.txt
1554293118.78 - keylime.ima - WARNING - No boot_aggregate value found in whitelist, adding an empty one
1554293118.8 - keylime.tenant - ERROR - Response code 404: instance id not found
1554293118.8 - keylime.tenant - DEBUG - b64_v:0ybTIXyfnPwNaUyHbZGEAoPd/Dst8gF9KR8OJlwq2G4=
1554293120.79 - keylime.tenant - DEBUG - cnquote received quote:reJz7H+Ls3iDBoMTA/Vf7fvKje28OBb1/vuSk5vl5BUf11UPFIqrNlDu4eD38NzOIuJfnhhXkZuV7eaSVlYUlpXgnWQYxgIDEvB9AkhHEZFQQYxVkENMAsxm4mUGCCjdFKhOdM12+2Nycq7Fp9939rno/ijbzNFU+Cn1+a/3xn24APh0ucA==:eJwBBgH5/gAUAAsBALSl1VCevWSaRKsjlTAOWU2KUAxwq3VUzBDF6uvvWQlVTyd7N2tczBdaSS9tTcpRq9PigVdHkL2b3ht8RIwLfKoWaJERSVkqFV7FHP9SfIeH4R+Vzcm5ib1HIMwUOvOmTnV/EmckhS7EMOH0dOfn3DYUbcZ9s+T8pzB2RHWKvo04kJlxE3f2/zZva0cerOg0F8ADxmclB2JCjXIT7mYOBM3oyLgw4h8Y+lHnX5nXFMJMySaP23iAPTNzGzJfgoz6a2ACwojEVWDcj5pzP+1eFi2G76c370dI/AlobX7TbdM2XnVsmdGTOsLgCugHU4liu/MbDWj/UZKfN9lIE/0RYnG+ZXoG:eJxjZGBg4GZgZmQYQMAIxQqEFDLT3CmjYBABAHgQADY=
1554293120.79 - keylime.tenant - DEBUG - cnquote received public key:-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwP5fJevFjh9YjP6iMQLY
Rtb0zj4jVrvs6fBzdU+s4iM/xiTQU7rzILnaqdHQibFOT2xE0vkk2cw8wLgbz6bk
EhSM4JJmjdCm/rZAidYfKc4bY38A73w3tULUIkHOkCMBbDJdIDMONbQ0bm+Z3jH3
2AQtXyxxMyd6012ttrm0juSd+ox0cJiff0RbI5xTt8Mb9cePrJIkGt0S+hlAbOuo
/rghKm9rLPopl3wsZr2h14W2Ld7AUOZk/WwhHJCmqaNK3uw6Z0nR2Cji+huJsscH
xA1VfkHhYwevciUlkEwIsknnQ/b65z5APdA/gF7N1WcYwUi3VEM42PP44xT+qVxe
VwIDAQAB
-----END PUBLIC KEY-----
1554293120.79 - keylime.tenant - DEBUG - cnquote received tpm version:2
1554293120.79 - keylime.tenant - DEBUG - cnquote received hash algorithm:sha256
1554293120.79 - keylime.tenant - DEBUG - cnquote received encryption algorithm:rsa
1554293120.79 - keylime.tenant - DEBUG - cnquote received signing algorithm:rsassa
1554293120.79 - keylime.registrar_client - INFO - Setting up client TLS...
1554293120.8 - keylime.registrar_client - WARNING - CAUTION: using default password for private key, please set private_key_pw to a strong password
1554293120.82 - keylime.tenant - WARNING - DANGER: EK cert checking is disabled and no additional checks on EKs have been specified with ek_check_script option. Keylime is not secure!!
1554293120.82 - keylime.tenant - INFO - Quote from 127.0.0.1 validated
1554293120.82 - keylime.tenant - DEBUG - b64_encrypted_u: u4Kzd0WlAgZkXNzvMsYTaNdYfKIih2M0nvxmPlOahDdqW9ic5zE9MZ3prPKVAnyx32UosFKPJmsm5G/r7a70ZWx85YlYG07JxYguqrcM4snCosy5M4+9yrSMiwLCKrVHqb2Dxjsyuy/2elofjrOdfgSWByMi2GD6w4lfOd2p7czb1VOgWS91DdWFomaFVvTbmiX3otnH96YoEZO7pneRSRmMTpgIbRLXdzE+1oq3MmuMxPPQaHa7Qf7hsYjof092V09PV5YGeOR/W65V1IcX7Km5mzVxXiZVO/1rjEnr8vnVlrY8UrtKBCA7HN19bYXQ2CJPH1lBP2ZcjLuTkWCIgA==
```

We then see the following reported on the keylime verifier:

```
1554293120.22 - keylime.tpm - INFO - Checking IMA measurement list...
1554293120.22 - keylime.ima - WARNING - File not found in whitelist: /usr/local/bin/tpm_with_ima.sh
1554293120.22 - keylime.ima - WARNING - File not found in whitelist: /usr/bin/keylime_ima_emulator
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_MD5.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_BLAKE2s.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Util/_strxor.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA384.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ecb.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_cbc.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_cfb.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ofb.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ctr.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA1.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA256.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_Salsa20.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Protocol/_scrypt.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Util/_cpuid_c.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_ghash_portable.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_ghash_clmul.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ocb.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA224.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA512.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_des.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_arc2.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_des3.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_aes.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_aesni.so
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/bin/keylime_verifier
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/bin/keylime_registrar
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/bin/keylime_agent
1554293120.23 - keylime.ima - WARNING - File not found in whitelist: /usr/bin/keylime_tenant
1554293120.23 - keylime.ima - ERROR - IMA ERRORS: template-hash 0 fnf 30 hash 0 good 446
1554293120.79 - keylime.cloudverifier - WARNING - Instance D432FBB3-D2F1-4A97-9EF7-75BD81C00000 failed, stopping polling
```

So what has happened here. Remember we generated are whitelist using the `initramfs` file system. However IMA has measured files that are not in our whitelist (files most related to us install keylime, thus the python dependencies in `/usr/lib/python2.7/` and the keylime entry point scripts)

There are two things we could do here. As an application developer, we could add our application files to the whitelist before provisioning, but to save time, for now we will add these to the `exclude.txt` file and then update the agent again.

```
# cat excludes.txt
/usr/local/bin/tpm_with_ima.sh
/usr/bin/keylime_ima_emulator
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_MD5.so
usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_BLAKE2s.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Util/_strxor.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA384.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ecb.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_cbc.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_cfb.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ofb.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ctr.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA1.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA256.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_Salsa20.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Protocol/_scrypt.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Util/_cpuid_c.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_ghash_portable.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_ghash_clmul.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_ocb.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA224.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Hash/_SHA512.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_des.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_arc2.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_des3.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_aes.so
/usr/lib/python2.7/site-packages/pycryptodomex-3.8.0-py2.7-linux-x86_64.egg/Cryptodome/Cipher/_raw_aesni.so
/usr/bin/keylime_verifier
/usr/bin/keylime_registrar
/usr/bin/keylime_agent
/usr/bin/keylime_tenant
```

Let's update the agent s `excludes.txt`

```
keylime_tenant -v 127.0.0.1 -t 127.0.0.1 -f /root/excludes.txt --uuid D432FBB3-D2F1-4A97-9EF7-75BD81C00000 --whitelist /root/whitelist.txt --exclude /root/excludes.txt -c update
```

We can now see the Agent performing tpm quotes (requested a signed event log of measurements from the TPM):

```
1554303836.38 - keylime.cloudagent - INFO - Decrypting payload to /var/lib/keylime/secure/decrypted_payload
1554303838.45 - keylime.cloudagent - INFO - GET invoked from ('127.0.0.1', 54198) with uri:/quotes/integrity?nonce=SIgdrwvWqNsRxuxxjdzo&mask=0x408400&vmask=0x808000&partial=1
1554303838.95 - keylime.cloudagent - INFO - GET integrity quote returning 200 response.
1554303841.38 - keylime.cloudagent - INFO - GET invoked from ('127.0.0.1', 54200) with uri:/quotes/integrity?nonce=dX3Pw7EsZJRyU5Jfo6ND&mask=0x408400&vmask=0x808000&partial=1
1554303841.93 - keylime.cloudagent - INFO - GET integrity quote returning 200 response.
1554303844.38 - keylime.cloudagent - INFO - GET invoked from ('127.0.0.1', 54202) with uri:/quotes/integrity?nonce=6kFJv3m7UVO1GWGj2ip1&mask=0x408400&vmask=0x808000&partial=1
1554303844.92 - keylime.cloudagent - INFO - GET integrity quote returning 200 response.
1554303847.37 - keylime.cloudagent - INFO - GET invoked from ('127.0.0.1', 54204) with uri:/quotes/integrity?nonce=WjmZZVwHxb2lj6rKHwtK&mask=0x408400&vmask=0x808000&partial=1
1554303847.88 - keylime.cloudagent - INFO - GET integrity quote returning 200 response.
```

And the verifier confirming

```
1554303903.92 - keylime.tpm - DEBUG - IMA measurement list validated
```

Let's now run a script not included in the whitelist

```
# whoami
root
# cat evil.sh
#!/bin/bash
echo -e "muahahaha!"

# ./evil.sh
muahahaha!
```

```
1554304101.23 - keylime.ima - WARNING - File not found in whitelist: /root/evil.sh
1554304101.23 - keylime.ima - ERROR - IMA ERRORS: template-hash 0 fnf 1 hash 0 good 453
1554304101.77 - keylime.cloudverifier - WARNING - Instance D432FBB3-D2F1-4A97-9EF7-75BD81C00000 failed, stopping polling
```

As we can see, the agent enters a failed state and polling stops. Actions can then be taken to revoke the agent.

For the next blog, we will look at setting up secure boot.
