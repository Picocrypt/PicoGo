# Dev Setup

- Developing on a windows machine inside of wls
- fyne-cross looks really promising for me to not have to do much setup myself
  - needed to download Docker Desktop for Windows
  - after than, `docker` inside ubuntu just worked
  - needed to make a FyneApp.toml file, see `App metadata` in fyne docs
  - running `~/go/bin/fyne-cross android -arch=arm64` just worked (tm) for hello world
  - need a nicer way to upload to my phone - just copying the file over manually for now

# Ideas for improvement
- carefully go through Picocrypt again and make sure I'm not missing little things (like comment length restriction)
- add screenshot to readme
- update icon
- add license
- decide what to do about not being able to delete content uris
  - specifically means I cannot support a delete button or clean up a decryption if it fails.
  - could decrypt to a fixed file, like headless does. Then only copy over if needed. Even so,
    the way Android is handling it, the save file is technically created on select, so a partial
    file will always appear to exist, regardless of if it is empty or whatever.
  - I could switch the order a bit and have it encrypt/decrypt to an internal file first, then
    ask the user where to save it once that works. Then you don't end up with extra empty files, and
    you could use that as the opportunity to do the recovery mode. Still no option to delete the
    original file, but that might just be the limit of content uris.
  - Maybe I could set up a specific folder somehow that has fixed path and I can make the file uri.
    - Call it the "vault"
    - User can manually add files to the vault, or delete them
    - Files are stored in the vault unencrypted. The interface would allow deleting, export encrypted,
      and export unencrypted. Maybe you actually store encrypted and go from there, same basic thing.
    - seems like a lot of work to enable the delete feature, which you still wouldn't have for copying
      in files. And you are "hiding" the files on the device, when the goal is for the files to be
      free to be stored or moved wherever.