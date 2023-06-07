# Send Requests, Regex Responses (SRRR)
        
## Requirements

- Burp Suite
- Jython 2.7.3

## Libraries

- burp
- javax.swing
- javax.swing.table
- java.awt
- java.io
- java.lang
- datetime
- urllib
- re

## Description

This custom Burp Extension written in python allows for:
- Requesting of multiple URLs
- Viewing the responses in a log table
- Returning interesting items in the response with regular expression

## Known Issues

- Sending with more than 10 URLs in the URL Field at once may freeze Burp Suite.
- Burp Logger will not detect the requests sent and responses recieved as urllib is used
- Request and response logs are not persistent, even if saved as a project.

## Usage

Navigate to the "SRRR" tab.

![SRRR v0.1 GUI](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/18fefb8bd7b463fb1cf8814dde9dab6d86505794/Images/SRRR%20GUI.png)

Input URLs to be requested, and click "Send Request"
Responses will appear in the log table below.
As the space is limited, items in log table may selected and copied out for your own further analysis.

![SRRR Request and Response](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/18fefb8bd7b463fb1cf8814dde9dab6d86505794/Images/SRRR%20Usage.png)

Navigate back to the Extensions tab to view the debug output or errors (if any)

![SRRR Console Output](https://github.com/TheSwagLord69/Burp-Suite-Custom-Extension/blob/4aa425187c3dc1e18ae7a46cabb58e68e91b5fbe/Images/SRRR%20Debug%20Messages.png)
