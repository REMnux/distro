# REMnux Distro Repository

This repository contains supplemental files for the [REMnux](https://REMnux.org) distro and the source files for the Debian packages that the distro installs from the [REMnux package repository](https://launchpad.net/~remnux/+archive/ubuntu/stable/+packages) on Launchpad.

## Repository Structure

### `files/`

Supplemental files used by the REMnux distribution, including:

- Helper scripts and utilities deployed during installation
- Mirror copies of dependencies for resilience

### `ppasrc/`

Source packages for Debian packages published to the [REMnux PPA](https://launchpad.net/~remnux/+archive/ubuntu/stable). Each subdirectory contains the packaging files for a specific tool, organized by Ubuntu release (Bionic, Focal, Noble).

## License

The REMnux project licenses the scripts and packaging files it created for this repository under the [GNU General Public License v3.0](LICENSE), unless stated otherwise. The tools packaged in `ppasrc/` keep their upstream licenses, and each package's `debian/copyright` file records them. Third-party files mirrored in `files/` also keep their own licenses.

## Related Resources

- [REMnux Website](https://REMnux.org)
- [REMnux Documentation](https://docs.remnux.org)
- [Salt States Repository](https://github.com/REMnux/salt-states) – Configuration management states that define the distro
