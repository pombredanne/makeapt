# makeapt

Debian APT repositories generator


## Usage

#### Create new empty APT repository

```
makeapt init
```

#### Add .deb files to existing repository

```
makeapt add <distribution> <component> <packages>...
```

For example:

```
makeapt add bionic main curl_7.58.0-2ubuntu3.3_amd64.deb
```
