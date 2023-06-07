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
