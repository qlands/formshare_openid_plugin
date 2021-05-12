FormShare OpenID Plugin
==============

This plug-in enable FormShare to become a OpenID server where third-party applications could use it to authenticate user accounts.

Getting Started
---------------

- Activate the FormShare environment.
```
$ . ./path/to/FormShare/bin/activate
```

- Change directory into your newly created plug-in.
```
$ cd openid
```

- Build the plug-in
```
$ python setup.py develop
```

- Add the plug-in to the FormShare list of plug-ins by editing the following line in development.ini or production.ini
```
    #formshare.plugins = examplePlugin
    formshare.plugins = openid
```

- Run FormShare again