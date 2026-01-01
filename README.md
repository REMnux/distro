# REMnux Distro Repository

This repository contains supplemental files for the [REMnux](https://REMnux.org) distro and the source files for the Debian packages that the distro installs from the [REMnux package repository](https://launchpad.net/~remnux/+archive/ubuntu/stable/+packages) on Launchpad.

## Repository Structure

### `files/`

Supplemental files used by the REMnux distribution, including:

- Helper scripts and utilities deployed during installation
- Mirror copies of dependencies for resilience

### `ppasrc/`

Source packages for Debian packages published to the [REMnux PPA](https://launchpad.net/~remnux/+archive/ubuntu/stable). Each subdirectory contains the packaging files for a specific tool, organized by Ubuntu release (Bionic, Focal, Noble).

## Related Resources

- [REMnux Website](https://REMnux.org)
- [REMnux Documentation](https://docs.remnux.org)
- [Salt States Repository](https://github.com/REMnux/salt-states) – Configuration management states that define the distro
