# REMnux Version 5 Installation Notes

[REMnux](http://remnux.org/) is available in several formats: an OVF/OVA virtual appliance, a VMware-specific virtual appliance and an ISO image of a Live CD. The main REMnux page includes instructions for [downloading REMnux](http://remnux.org/#distro) and installing its virtual appliance. For detailed instructions specific to the OVF/OVA version, see the article [Installing the REMnux Virtual Appliance for Malware Analysis](http://computer-forensics.sans.org/blog/2013/04/10/installing-remnux-virtual-appliance).

Below is an outline of several installation challenges, issues and workarounds for installing REMnux.

## Upgrading Viper on REMnux

[Viper](https://github.com/botherder/viper) is "a framework to store, classify and investigate binary files." After REMnux v5 was released, Viper was [updated to include additional functionality](http://digital-forensics.sans.org/blog/2014/06/04/managing-and-exploring-malware-samples-with-viper). To update Viper on REMnux, connect your REMnux virtual appliance to the Internet, then:

    sudo -s
    cd /usr/local
    rm -rf viper
    git clone https://github.com/botherder/viper.git
    pip install OleFileIO_PL
    pip install bottle
    mkdir ~remnux/projects

Next, modify the /usr/local/viper/modules/pe.py, replacing the reference to "data/peid/UserDB.txt" with "/usr/local/viper/data/peid/UserDB.txt".

Also, modify /usr/local/viper/modules/yarascan.py, replacing the reference to "data/yara/index.yara" with "/usr/local/viper/data/yara/index.yara".

You can now run the updated Viper tool (viper.py) as the non-root user "remnux". Do this from a directory to which the "remnux" user has write access, such as the user's home directory.

## VirtualBox on Linux: Unknown Element "Config"

Some people encountered a problem installing the REMnux OVF/OVA virtual appliance using VirtualBox on Linux. This is not an issue with VirtualBox running on Windows. When importing the virtual appliance on Linux using VirtualBox, you might encounter the following error:

    Failed to import appliance remnux-5.0-ovf-public.ovf.
    Error reading "remnux-5.0-ovf-public.ovf": unknown element "Config" under Item element, line 47.
    Result Code: VBOX_E_FILE_ERROR (0x80BB0004)
    Component: Appliance
    Interface: IAppliance {3059cf9e-25c7-4f0b-9fa5-3c42e441670b}

To address this problem, first, extract contents of remnux-5.0-ovf-public.ova using tar:

    tar xvfz remnux-5.0-ovf-public.ova

Then, use a text editor to modify the remnux-5.0-ovf-public.ovf file to remove all "Config" lines:

    <vmw:Config ovf:required="false" vmw:key="ehciEnabled" vmw:value="true"/>
    <vmw:Config ovf:required="false" vmw:key="wakeOnLanEnabled" vmw:value="false"/>
    <vmw:Config ovf:required="false" vmw:key="tools.syncTimeWithHost" vmw:value="false"/>

After saving the file, compute the modified file's SHA1:

    sha1sum remnux-5.0-ovf-public.ovf

Then save the resulting hash into the remnux-5.0-ovf-public.mf file, so that its contents look like this:

    SHA1(remnux-5.0-ovf-public.ovf)= cab3570a993adbe332708d44242139fa78e281d5
    SHA1(remnux-5.0-ovf-public-disk1.vmdk)= 09ced1f28b2a654d235701350cc3f84bfd1ec772

Your SHA1 value of the OVF file will be different from the values shown above and will depend on how you edited the OVF file.

After you've taken these steps, you should should be able to import the REMnux virtual machine into VirtualBox on Linux by pointing VirtualBox to the remnux-5.0-ovf-public.ovf file.

## VirtualBox on Linux: Nonexistent Host Networking Interface

Some people reported a problem reported a problem launching the imported REMnix virtual system when using VirtualBox on Linux. This is not a problem with VirtualBox running on Windows. The error they saw stated:

    Nonexistent host networking interface, name '' (VERR_INTERNAL_ERROR).
    Result Code: NS_ERROR_FAILURE (0x80004005)
    Component: Console
    Interface: IConsole {1968b7d3-e3bf-4ceb-99e0-cb7c913317bb}

This issue is tied to the host-only adapter not being configured by VirtualBox for the virtual system. To address it, assign the Host-Only Ethernet Adapter to the virtual system using VirtualBox. The following step-by step directions are based on [CS50.net documentation](https://manual.cs50.net/VirtualBox#Nonexistent_host_networking_interface.2C_name_.27.27_.28VERR_INTERNAL_ERROR.29):

  1. Select Preferences... under VirtualBox's File menu, then click Network.
  2. "If VirtualBox Host-Only Ethernet Adapter does not already appear in the white box under Host-only Networks, click the icon to the right of that box, and VirtualBox Host-Only Ethernet Adapter should then appear in the box."

## Converting to KVM Format: Error Using "`qemu-img convert`"

In addition to importing the OVF/OVA-formatted virtual appliance into tool such as VMware and VirtualBox, you can convert the VMware-formatted REMnux virtual appliance for use with KVM virtualization software. To do this, download and extract the remnux-5.0-vm-public.zip file. You could also use the OVF/OVA-formatted virtual appliance, but then you would need to first extract the files prior to conversion by using the "tar" command mentioned above.

Use the QEMU "`qemu-img convert`" command to convert the REMnux VMDK file into the qcow2 format.

You might need to first upgrade qemu-img from the git repository to address a [known QEMU bug on CentOS](https://bugs.launchpad.net/qemu/+bug/1075252). The error might look like this:

    qemu-img info remnux-5.0-ovf-public-disk1.vmdk
    qemu-img: Could not open 'remnux-5.0-ovf-public-disk1.vmd

To address this problem, use the latest version of qemu-img from its git repository, instead of using the [qemu-img package from the CentOS repository](http://git.qemu.org/qemu.git).

## Running REMnux in Hyper-V: Spurious ACK

Some users reported problems when running the Live CD version of REMnux as a virtual machine inside Microsoft [Hyper-V](http://www.microsoft.com/en-us/server-cloud/hyper-v-server/default.aspx). The error they encountered when booting the system said:

    Spurious ACK... Some program might be trying to access hardware directly

This problem might be related to the virtual hardware that Hyper-V uses for the network interface card, which might not be compatible with Linux. This issue and several potential workaround are discussed [here](http://www.vyatta.org/node/6236) and [here](http://www.vyatta.org/comment/22399#comment-22399).

A good workaround might be to convert the REMnux virtual appliance from the VMware format into the Hyper-V format using [StarWind V2V Converter](http://www.starwindsoftware.com/converter).
