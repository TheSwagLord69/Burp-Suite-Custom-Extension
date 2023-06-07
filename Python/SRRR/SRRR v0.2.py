"""
Script Name: SRRR v0.2.py
Author: Dominic Gian
Date: June 5, 2023
Description: Send Requests, Regex Responses (SRRR). This custom Burp Extension allows for requesting of multiple URLs, viewing the responses and searching the responses with regular expression for any interesting artifacts.
Version: 0.2
License: MIT License
Requirements: Jython 2.7.3 as the Python environment in Burp Suite.
Known Bugs/Issues: 
- More than 10 URLs at once may freeze Burp Suite.
- Burp Logger will not detect the requests sent and responses recieved as it uses urllib.
- Request and response logs are not persistent.
Possible future development:
- Export log table as a file (.csv maybe?)
- Replace urllib with httplib
- Use the default IBurpExtender to send and recieve HTTP instead of python libraries
"""

# Import libraries
from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import JPanel, JButton, JTextArea, JScrollPane, JTabbedPane, JTextField
from datetime import datetime
from javax.swing.table import DefaultTableModel
from java.awt import BorderLayout, GridLayout, FlowLayout
from javax.swing import JTable, ListSelectionModel
from java.io import PrintWriter
from java.lang import RuntimeException
import urllib
import re

# Global Regex Variable
regex = r"(?:<title>)(.*?)(?:<\/title>)"

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        # Extension callbacks and helper objects
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Send Requests, Regex Responses")
        callbacks.registerHttpListener(self)

        # Obtain our output and error streams
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Banner
        self.stdout.println("================================================================") # debug
        self.stdout.println("   ____            __  ___                       __             ") # debug
        self.stdout.println("  / __/__ ___  ___/ / / _ \___ ___ ___ _____ ___/ /____         ") # debug
        self.stdout.println(" _\ \/ -_) _ \/ _  / / , _/ -_) _ `/ // / -_|_-< __(_-<         ") # debug
        self.stdout.println("/___/\__/_//_/\_,_/ /_/|_|\__/\_, /\_,_/\__/___|__/___/         ") # debug
        self.stdout.println("  / _ \___ ___ ______ __  / _ \/_/ ___ ___  ___  ___  ______ ___") # debug
        self.stdout.println(" / , _/ -_) _ `/ -_) \ / / , _/ -_|_-</ _ \/ _ \/ _ \(_-< -_|_-<") # debug
        self.stdout.println("/_/|_|\__/\_, /\__/_\_\ /_/|_|\__/___/ ___/\___/_//_/___|__/___/") # debug
        self.stdout.println("         /___/                      /_/                    v0.1 ") # debug
        self.stdout.println("================================================================") # debug

        # Main panel
        self.panel = JPanel(BorderLayout())

        # Tabbed pane
        self.tabbedPane = JTabbedPane()
        
        # Create the panel for the main tab
        mainPanel = JPanel(BorderLayout())
        
        # Create the panel for the second tab
        secondPanel = JPanel(BorderLayout())
        
        # Add the main panel and second panel to the tabbed pane
        self.tabbedPane.addTab("Main", mainPanel)
        self.tabbedPane.addTab("Config", secondPanel)
        
        # Create the panel for the upper half of the components in the main tab
        upperPanel = JPanel()
        upperPanel.setLayout(FlowLayout())
        
        # Create the panel for the lower half of the components in the main tab
        lowerPanel = JPanel()
        lowerPanel.setLayout(GridLayout(1, 1))
        
        # Add the upper and lower panels to the main panel in the main tab
        mainPanel.add(upperPanel, BorderLayout.NORTH)
        mainPanel.add(lowerPanel, BorderLayout.CENTER)
        
        # Configure url field
        self.urlField = JTextArea("https://example.com", rows=10, columns=69)
        urlScrollPane = JScrollPane(self.urlField) # Make urlField scrollable
        # Configure send button
        self.sendButton = JButton("Send Request", actionPerformed=self.sendRequest)
        # Configure log table
        self.logTable = JTable(DefaultTableModel(["Timestamp", "Request URL", "Status", "Method", "Raw Body", "Headers", "Interesting Items"], 0)) # Define table column headers
        self.logTable.setAutoCreateRowSorter(True) # Allow table columns to be sorted by clicking
        self.logTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION) # Ensure that only one row can be selected at a time
        logScrollPane = JScrollPane(self.logTable) # Make logTable scrollable
        
        # Add components to the panels in the Main tab
        upperPanel.add(urlScrollPane, BorderLayout.CENTER)
        upperPanel.add(self.sendButton, BorderLayout.LINE_END)
        lowerPanel.add(logScrollPane, BorderLayout.CENTER)
        
        # Configure regex field
        self.regexField = JTextField(str(regex), columns=50) #get regex from global
        self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tDefault Regex String: '" + str(regex) + "'") # debug
        # Configure update regex button
        self.updateRegexButton = JButton("Update Regex", actionPerformed=self.updateRegex)
        
        # Add components to the panels in the second tab
        secondPanel.add(self.regexField, BorderLayout.NORTH)
        secondPanel.add(self.updateRegexButton, BorderLayout.SOUTH)

        # Add the tabbed pane to the main panel
        self.panel.add(self.tabbedPane, BorderLayout.CENTER)

        # Customize the appearance of the UI components in line with Burp's UI style, including font size, colors, table line spacing, etc. using the Burp callbacks object 
        callbacks.customizeUiComponent(self.panel)
        
        # Add a custom tab to the main Burp Suite window
        callbacks.addSuiteTab(self)
        
        self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tExtension Loaded") # debug

    def updateRegex(self, event):
        global regex
        regex = str(self.regexField.getText())
        self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tRegex String: '" + str(regex) + "'") # debug

    # Send the HTTP requests for URLs in the input field using urllib
    def sendRequest(self, event):
        try:
            # Get individual URLs from the input field
            urls = self.urlField.getText().splitlines()
            self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tURLs to be requested:\t" + str(urls)) # debug

            # Iterate through the URLs
            for url in urls:
                self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tCurrently requesting:\t" + str(url)) # debug
                current_url = url  # Store the current URL in a separate variable

                try:
                    # Send request
                    #params = urllib.urlencode({'spam': 1, 'eggs': 2, 'bacon': 0}) # For POST using urllib
                    #response = urllib.urlopen(url, params) # For POST using urllib
                    response = urllib.urlopen(url) # For GET using urllib
                    self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tGot response for " + str(url)) # debug

                    # Read headers
                    response_headers_list = []
                    headers = response.info()
                    for key, value in headers.items():
                        response_headers_list.append(str(key) + ": " + str(value))
                    
                    # Read response
                    response_data = response.read().decode('utf-8', errors='ignore') # Ignores all non UTF-8 characters, else an exception will occur.
                    
                    # Timestamp of event
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # Response Status Code
                    status_code = str(response.getcode())
                    
                    # Request Method used
                    method = "GET" # TODO POST Request?
                    
                    # Search XML for any "interesting" artifacts
                    interesting_list = []
                    results = re.findall(regex, response_data, re.DOTALL | re.UNICODE)
                    
                    if results is not None and results is not "":
                        for i in results:
                            i = i.encode('utf-8', errors='ignore').decode('utf-8')
                            interesting_list.append(i)
                            
                    # Update log table
                    self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tAdding " + str(current_url) + " to log table.") # debug
                    log_entry = [timestamp, current_url, status_code, method, response_data, response_headers_list, interesting_list]
                    self.updateLogTable(log_entry)
                    self.stdout.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tSuccessfully added " + str(current_url) + " to log table.") # debug

                # Handle exceptions
                except IOError as e:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = [timestamp, current_url, "IOError", "", str(e)]
                    self.stderr.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tIOError:\t" + str(e))
                    self.updateLogTable(log_entry)
                except Exception as e:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    log_entry = [timestamp, current_url, "Exception", "", str(e)]
                    self.stderr.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tException:\t" + str(e))
                    self.updateLogTable(log_entry)

        # Handle exceptions
        except RuntimeError as e:
            self.stderr.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tRuntimeError:\t" + str(e))
        except Exception as e:
            self.stderr.println("[*]\t" + str(datetime.now().strftime('%Y-%m-%d %H:%M:%S')) + "\tException:\t" + str(e))

    # Update log table
    def updateLogTable(self, log_entry):
        self.logTable.getModel().addRow(log_entry)

    # Custom tab title
    def getTabCaption(self):
        return "SRRR"

    # Return the UI component to be displayed as the content of the custom tab
    def getUiComponent(self):
        return self.panel
