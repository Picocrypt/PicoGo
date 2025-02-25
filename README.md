# PicoGo

A mobile app for file encryption compatible with [Picocrypt](https://www.github.com/Picocrypt/Picocrypt).

This app is based on Picocrypt's encryption scheme but is not developed or endorsed by Picocrypt's author/maintainer. It is a standalone work intended to make Picocrypt files easier to access on Android devices. All credit for the original encryption scheme and corresponding code belongs to [Picocrypt](https://www.github.com/Picocrypt/Picocrypt) and it's author [HACKERALERT](https://github.com/HACKERALERT).

> [!CAUTION]
> PicoGo is still in an experimental phase. It has not been extensively tested yet and so is not recommended for securing important files. If you do so, test the result compared to Picocrypt to be sure. If you run into any errors, please open an issue.

> [!IMPORTANT]
> Feedback needed! If you are willing, I am looking for early testers for the UI and starting feature set. If you could take a few minutes to try the app out and leave any comments or suggestions it would go a long way in helping PicoGo a usable app for everyone.

# Features

Most Picocrypt features are supported
- [x] Standard encryption
- [x] Comments
- [x] Paranoid mode
- [x] Deniability mode
- [x] Keyfiles (with and without ordering)
- [x] Reed Solomon redundancy
- [x] Recovery mode

# Installation

## Google Play

Coming soon! Once I smooth out some rough edges and complete sufficient testing, I intend to make PicoGo available on the Google Play store.

## Manual Installation

Download the latest [release](https://github.com/njhuffman/picogo/releases) into your Android device. When the download is finished, the device should offer to automatically install the app for you.

You may receive a warning message with wording like `Unsafe app blocked. This app was built for an older version of Android and doesn't include the latest privacy protections.` This warning happens because I build the app with Fyne who maintains backwards compatibility with older devices. Tap on `More details` and `Install anyway`.

## Build from source

To build PicoGo from source I recommend using [fyne-cross](https://docs.fyne.io/started/cross-compiling.html). Once set up, just clone this repo and run `fyne-cross android -arch=arm64` to build the app. This should create a `PicoGo.apk` file you can install directly to an Android device.

# Missing Features

Unsupported features are listed below. If you would like to see any of them implemented, feel free to open a issue and we can see what features would be useful and implementable on mobile.

## What about file chunks?

There are no plans to support file chunking. PicoGo is built using [Fyne.io](https://www.fyne.io) which does not offer an easy way to look up files on Android by name. This would require the user to manually select each of the chunked files, which seems clumsy and unnecessarily complex.

## What about multiple files / zip / compression?

Similar problem as file chunks. Fyne exposes files as content URIs, so there is no easy way to map input filenames to output filenames the way that Picocrypt does. I don't want to make the user manually select the save file for each input file, so right now I am only accepting one input file at a time. For zipping and compression, I recommend using other apps to prepare the zip file and then selecting that directly within PicoGo.

## What about iOS devices?

In theory, the app is fully ready to be built for iOS. Unfortunately I do not have easy access to an apple silicon device (required to run the build process) or any iOS devices to test with. Even if both of those are solved, distributing apps for iOS devices costs about $100 per year for a developer license, which is higher than I'm willing to commit right now. Fyne doesn't even build an iOS app unless you have a developer certificate.

# Credits
<ul>
  <li><strong><a href="https://github.com/njhuffman">@njhuffman</a></strong>: initial and primary developer of PicoGo</li>
  <li><strong><a href="https://github.com/HACKERALERT">@HACKERALERT</a></strong>: original Picocrypt developer, PicoGo CI/CD maintainer</li>
</ul>
