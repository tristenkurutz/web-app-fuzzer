# fuzzer
In the current state, the Fuzzer application is capable of:
- Using authorization on the DVWA web app.
- Creating the database and changing the security level.
- Using a file of common words, can guess links that possibly exist.
- Based on the user-given starter URL and the guessed links, crawls webpages for links.
- Using a file of vectors, can determine whether there is an injection vulnerability.
- Determining if there are possibly any bad responses upon submitting a vector.
- Determining if any sensitive information from a file is being leaked through responses.


## requirements
- SWEN 331 Docker Image
- MechanicalSoup

## run the application

```python fuzz.py discover [url] --custom-auth=dvwa --common-words=[file] --vectors=[file] --sensitive=[file]```

<details><summary>commands and arguments (click to expand)</summary>
<b>commands:</b>
<blockquote><b>discover:</b> Output a comprehensive, human-readable list of all discovered inputs to the system. Techniques include both crawling and guessing.</blockquote>

<b>arguments:</b>
<blockquote><b>--custom-auth:</b> Signal that the fuzzer should use hard-coded authentication for a specific application (e.g. dvwa)</blockquote>
<blockquote><b>--common-words:</b> Define where the common word guesser text file is</blockquote>
<blockquote><b>--vectors:</b> Define where the vector input text file is</blockquote>
<blockquote><b>--sensitive:</b> Define where the sensitive data input text file is</blockquote>
<blockquote><b>--sanitized-chars:</b> Define the file path of characters separated by new lines to test to determine whether an input has been sanitized.</blockquote>

</details>
