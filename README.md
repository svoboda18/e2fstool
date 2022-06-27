e2fstool
=================
- (advanced) (Android) ext4 image extractor tool with support for Windows.

## Main features:
- Extracts sparse images without conversion.
- Extracts android-ified inodes xattars. (capabilities, selinux contexts)
- Treats config paths correctly and works with SaR extraction. (`-m /`)
- Works if compiled using Windows API (aka MINGW32)
- Uses CYGWIN symlinks (for WIN32) so that it is compatible with most-known repacking tools.

## Build process:
* Clone this repo.
* Build `e2fstool` with your desired gcc.
* You will need have `libext2_com_err libext2fs libsparse libbase libz` sources prepared. (Note that `libbase` is only required for newer `libsparse` builds)
  - In addition to that, for WIN32 targets, and earlier `libbase` builds, `libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll` must be present in your execution environment. (PATH)
* Run `e2fstool` for command line arguments usage.

## Credits:
* All credits goes to the author (@svoboda18)
* GNU e2fsprogs
