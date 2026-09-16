# Publishing to the AUR

Two packages, following the usual Arch convention: `asli` builds from source, `asli-bin` unpacks the
released tarball. Publishing both is normal and expected, since people who avoid long Rust builds
want the second one.

## Before every release

The checksums in both files are placeholders. Replace them, or the package will not build in a
clean chroot:

```sh
cd packaging/aur
updpkgsums                 # rewrites sha256sums in PKGBUILD
```

For `PKGBUILD-bin`, take the sums straight from the release's `SHA256SUMS` asset rather than
downloading the tarballs a second time.

## Test in a clean chroot, not on your own machine

A package that builds only on the maintainer's machine is the most common AUR complaint, and the
cause is almost always a dependency that was already installed locally and missing from `depends`.

```sh
sudo pacman -S devtools
extra-x86_64-build         # builds in a clean chroot
namcap PKGBUILD
namcap asli-*.pkg.tar.zst
```

## First publication

```sh
git clone ssh://aur@aur.archlinux.org/asli.git aur-asli
cd aur-asli
cp ../PKGBUILD .
makepkg --printsrcinfo > .SRCINFO
git add PKGBUILD .SRCINFO
git commit -m "Initial import: asli 0.1.0"
git push
```

Repeat with `PKGBUILD-bin` copied to `aur-asli-bin/PKGBUILD`.

## Every update after that

`.SRCINFO` must be regenerated whenever `PKGBUILD` changes. The AUR reads package metadata from that
file, not from the `PKGBUILD`, so a stale one shows users the wrong version.

```sh
makepkg --printsrcinfo > .SRCINFO
git commit -am "asli 0.2.0"
git push
```
