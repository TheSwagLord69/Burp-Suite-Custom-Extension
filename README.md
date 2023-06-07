# Burp Suite Custom Extensions
Custom Extensions for Burp Suite

## Useful Documentation
https://portswigger.net/burp/extender/api/index.html
https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html
https://portswigger.net/burp/extender/api/burp/iextensionhelpers.html

## Python-based Extensions

### Setting up Jython
Jython can be downloaded at https://www.jython.org/download.html

![Jython Download](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/d0fe7db835b615ad160c3888a975269afbab4e8a/Images/Jython%20Download.png)

Go into Burp Settings

![Burp Settings](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/eb03856e22afa3bc86035bb8d7d0af37bca449c9/Images/Burp%20Settings.png)

Select Jython jar file

![Jython Path](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/69b00b9a06e57a0b34281a1069e886cabd3266c4/Images/Jython%20Path.png)

### Loadding a custom extension into Burp Suite

Navigate to "Extensions" tab. Under "Burp extensions", click "Add"

![Extensions Tab](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/70528818b614c2d01e09dffe015927825b53f4ec/Images/Burp%20Add%20Extension.png)

Choose the appropriate extension type and select the burp extension file to be loaded. 

![Load Extension](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/70528818b614c2d01e09dffe015927825b53f4ec/Images/Burp%20Load%20Extension.png)

Example of loading a custom burp extension. Click "Next".

![Selected File](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/70528818b614c2d01e09dffe015927825b53f4ec/Images/Burp%20Load%20Extension%20Selected%20File.png)

If the burp extension has no errors, it should load successfully.

![Loaded Sucessfully](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/70528818b614c2d01e09dffe015927825b53f4ec/Images/Burp%20Load%20Extension%20Success.png)

Navigating back to the Extensions Tab, we can see that it has loaded into Burp Suite.

![Custom Extension in Burp Suite](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/70528818b614c2d01e09dffe015927825b53f4ec/Images/Burp%20Extension%20is%20loaded.png)
