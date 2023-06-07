# Burp Suite Custom Extensions

## Disclaimer

The custom extension(s) provided in this repository are intended to enhance the functionality of Burp Suite and assist in web application security testing. 
While these extension(s) have been developed with care and are meant to be useful, they are community-contributed and not officially supported by the Burp Suite development team.

It's important to note that the use of these custom extension(s) carries inherent risks. 
Improper use or misconfiguration of the extension(s) may lead to unexpected behavior, false positives, or false negatives in security testing. 
It is strongly recommended to thoroughly understand the functionality and implications of each extension before utilizing them in your testing environment.

Furthermore, the authors and contributors of these extensions cannot be held responsible for any damages, vulnerabilities, or legal implications that may arise from their use. 
It is your responsibility to ensure compliance with applicable laws and regulations and to exercise caution when testing web applications, respecting the rights and privacy of others.

Always use these custom extensions responsibly and in accordance with ethical hacking guidelines. 
Regularly update both the extensions and Burp Suite itself to benefit from the latest security patches and improvements. 
Remember that no tool or extension can guarantee the detection of all vulnerabilities, and manual verification is crucial for a comprehensive security assessment.

By using these custom extensions, you acknowledge and accept the above disclaimer, taking full responsibility for any consequences that may result from their usage.

## Introduction

Burp Suite is widely used by security professionals and penetration testers for discovering vulnerabilities in web applications. 

While off the shelf, it offers a comprehensive set of features out of the box, this repository aims to extend its capabilities even further with custom extensions. 

These custom extensions leverage the extensibility of Burp Suite and provide additional functionality tailored to specific security testing scenarios. 

## Extension Descriptions

1. SRRR: Sends Request(s), and has the ability to Regex the Responses

## Environment Setup

### Python-based Extensions

#### Setting up Jython
Jython can be downloaded at https://www.jython.org/download.html

![Jython Download](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/d0fe7db835b615ad160c3888a975269afbab4e8a/Images/Jython%20Download.png)

Go into Burp Settings

![Burp Settings](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/eb03856e22afa3bc86035bb8d7d0af37bca449c9/Images/Burp%20Settings.png)

Select Jython jar file

![Jython Path](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/69b00b9a06e57a0b34281a1069e886cabd3266c4/Images/Jython%20Path.png)

#### Loadding a custom extension into Burp Suite

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

## Useful Documentation

https://portswigger.net/burp/extender/api/index.html
https://portswigger.net/burp/extender/api/burp/iburpextendercallbacks.html
https://portswigger.net/burp/extender/api/burp/iextensionhelpers.html
