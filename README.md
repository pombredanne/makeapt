# makeapt

Debian APT repositories generator


## Usage examples

#### Creating new empty APT repository

```
makeapt init
```

#### Adding .deb files to existing repository

```
makeapt add bionic:main packages/*.deb
```

#### Generating repository indexes

```
makeapt index
```

#### Displaying current configuration

```
makeapt config
```

#### Setting custom origin and label values

```
makeapt config origin 'My Origin'
makeapt config label 'My Label'
makeapt index  # Re-generate indexes.
```
