# Simple Key Store
A simple key store to use a password to decrypt parts of a file. This app is a simple way to protect API Tokens and Other secrets best not left in the clear file system.

## Usage
### Execute:
`enc.py --file /path/to/some/file.enc`

### Run
The user is asked for a password.  The first password for a new file path will set the password that is used to unlock the file.
* `File Password:`

Once the password successfuly decrypts a part of the title list, the user will then be presented with a menu where they can select:
```
          Choose:
                 l   : List all Vars
                 a   : Add or edit a value in the list. To add, no
                 x n : Display Decrypted value record n
                 d n : Delete a record n
                 e   : Exit
```

From this menu you can list Names, Add or Edit by Name, Display or Delete by Name Record Number.
