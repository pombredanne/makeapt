# makeapt

Debian APT repositories generator


## Usage

#### Create new empty APT repository

```
makeapt init
```

#### Add .deb files to existing repository

```
makeapt add <group> <paths>...
```

For example:

```
makeapt add bionic:main packages/*.deb
```

#### Generate repository indexes

```
makeapt index
```
