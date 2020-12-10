### What is this for
Use this while we can't find a static address easily in game hacking.

### Usage
> + Open project, replace the `vector<int> sig` with your own signature;
> + Build project to get `x64SignatureScanning.dll`;
> + Inject it to target process;
> + Press `Home` to start scanning.

### Debug
> + Go to `Debug` option, click `Attach to process`;
> + Select target process;
> + Make a breakpoint;
> + Build to get dll then inject it;
> + Debug whatever you want.

### Effect
Example test with Grand Theft Auto 5(GTA5) local player address scanning.
sinagature : `0x68, 0xEA, 0xDD, 0x7D, 0xF6, 0x7F, 0x00`
![effect](https://github.com/ESP0xA/x64SignatureScanning/blob/master/effect.jpg)
